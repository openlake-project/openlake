use std::fmt::Display;

use hyper::{
    HeaderMap, Method, Version,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde::Serialize;
use url::Url;

#[cfg(feature = "multipart")]
use crate::multipart;
use crate::{Body, Client, Response, Result};

/// A request which can be executed with `Client::execute()`.
#[derive(Debug)]
pub struct Request {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Body,
    version: Version,
}

impl Request {
    /// Constructs a new request.
    #[inline]
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: HeaderMap::new(),
            body: Body::empty(),
            version: Version::default(),
        }
    }

    /// Get the method.
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Get a mutable reference to the method.
    #[inline]
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }

    /// Get the url.
    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Get a mutable reference to the url.
    #[inline]
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// Get the headers.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get a mutable reference to the headers.
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Get the body.
    #[inline]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Get a mutable reference to the body.
    #[inline]
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Get the http version.
    #[inline]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get a mutable reference to the http version.
    #[inline]
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    pub(super) fn pieces(self) -> (Method, Url, HeaderMap, Body, Version) {
        (self.method, self.url, self.headers, self.body, self.version)
    }
}

/// A builder to construct the properties of a `Request`.
#[derive(Debug)]
pub struct RequestBuilder {
    client: Client,
    request: Request,
}

impl RequestBuilder {
    /// Assemble a builder starting from an existing `Client` and a `Request`.
    pub fn new(client: Client, request: Request) -> RequestBuilder {
        RequestBuilder { client, request }
    }

    /// Add a `Header` to this Request.
    pub fn header<K: TryInto<HeaderName>, V: TryInto<HeaderValue>>(
        self,
        key: K,
        value: V,
    ) -> Result<RequestBuilder>
    where
        K::Error: Into<http::Error>,
        V::Error: Into<http::Error>,
    {
        self.header_sensitive(key, value, false)
    }

    /// Add a `Header` to this Request with ability to define if `header_value`
    /// is sensitive.
    fn header_sensitive<K: TryInto<HeaderName>, V: TryInto<HeaderValue>>(
        mut self,
        key: K,
        value: V,
        sensitive: bool,
    ) -> Result<RequestBuilder>
    where
        K::Error: Into<http::Error>,
        V::Error: Into<http::Error>,
    {
        let key: HeaderName = key.try_into().map_err(|e| crate::Error::Http(e.into()))?;
        let mut value: HeaderValue = value.try_into().map_err(|e| crate::Error::Http(e.into()))?;
        // We want to potentially make an unsensitive header
        // to be sensitive, not the reverse. So, don't turn off
        // a previously sensitive header.
        if sensitive {
            value.set_sensitive(true);
        }
        self.request.headers_mut().append(key, value);
        Ok(self)
    }

    /// Add a set of Headers to the existing ones on this Request.
    ///
    /// The headers will be merged in to any already set.
    pub fn headers(mut self, headers: HeaderMap) -> RequestBuilder {
        crate::util::replace_headers(self.request.headers_mut(), headers);
        self
    }

    /// Enable HTTP basic authentication.
    ///
    /// ```rust
    /// # use cyper::Error;
    ///
    /// # async fn run() -> Result<(), Error> {
    /// let client = cyper::Client::new();
    /// let resp = client
    ///     .delete("http://httpbin.org/delete")?
    ///     .basic_auth("admin", Some("good password"))?
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_auth<U: Display, P: Display>(
        self,
        username: U,
        password: Option<P>,
    ) -> Result<RequestBuilder> {
        let header_value = crate::util::basic_auth(username, password);
        self.header_sensitive(AUTHORIZATION, header_value, true)
    }

    /// Enable HTTP bearer authentication.
    pub fn bearer_auth<T: Display>(self, token: T) -> Result<RequestBuilder> {
        let header_value = format!("Bearer {token}");
        self.header_sensitive(AUTHORIZATION, header_value, true)
    }

    /// Set the request body.
    pub fn body<T: Into<Body>>(mut self, body: T) -> RequestBuilder {
        *self.request.body_mut() = body.into();
        self
    }

    /// Sends a multipart/form-data body.
    ///
    /// In addition to the request's body, the Content-Type and Content-Length
    /// fields are appropriately set.
    #[cfg(feature = "multipart")]
    pub fn multipart(self, mut multipart: multipart::Form) -> Result<RequestBuilder> {
        let mut builder = self.header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={}", multipart.boundary()).as_str(),
        )?;

        builder = match multipart.compute_length() {
            Some(length) => builder.header(http::header::CONTENT_LENGTH, length)?,
            None => builder,
        };

        *builder.request.body_mut() = multipart.stream();
        Ok(builder)
    }

    /// Modify the query string of the URL.
    ///
    /// Modifies the URL of this request, adding the parameters provided.
    /// This method appends and does not overwrite. This means that it can
    /// be called multiple times and that existing query parameters are not
    /// overwritten if the same key is used. The key will simply show up
    /// twice in the query string.
    /// Calling `.query(&[("foo", "a"), ("foo", "b")])` gives `"foo=a&foo=b"`.
    ///
    /// # Note
    /// This method does not support serializing a single key-value
    /// pair. Instead of using `.query(("key", "val"))`, use a sequence, such
    /// as `.query(&[("key", "val")])`. It's also possible to serialize structs
    /// and maps into a key-value pair.
    ///
    /// # Errors
    /// This method will fail if the object you provide cannot be serialized
    /// into a query string.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Result<RequestBuilder> {
        let url = self.request.url_mut();
        {
            let mut pairs = url.query_pairs_mut();
            let serializer = serde_urlencoded::Serializer::new(&mut pairs);
            query.serialize(serializer)?;
        }
        if let Some("") = url.query() {
            url.set_query(None);
        }
        Ok(self)
    }

    /// Set HTTP version
    pub fn version(mut self, version: Version) -> RequestBuilder {
        self.request.version = version;
        self
    }

    /// Send a form body.
    ///
    /// Sets the body to the url encoded serialization of the passed value,
    /// and also sets the `Content-Type: application/x-www-form-urlencoded`
    /// header.
    ///
    /// ```rust
    /// # use cyper::Error;
    /// # use std::collections::HashMap;
    /// #
    /// # async fn run() -> Result<(), Error> {
    /// let mut params = HashMap::new();
    /// params.insert("lang", "rust");
    ///
    /// let client = cyper::Client::new();
    /// let res = client
    ///     .post("http://httpbin.org")?
    ///     .form(&params)?
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails if the passed value cannot be serialized into
    /// url encoded format
    pub fn form<T: Serialize + ?Sized>(mut self, form: &T) -> Result<RequestBuilder> {
        let body = serde_urlencoded::to_string(form)?;
        self.request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        Ok(self.body(body))
    }

    /// Send a JSON body.
    ///
    /// # Errors
    ///
    /// Serialization can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    #[cfg(feature = "json")]
    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Result<RequestBuilder> {
        let body = serde_json::to_string(json)?;
        if !self.request.headers().contains_key(CONTENT_TYPE) {
            self.request
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        Ok(self.body(body))
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    pub fn build(self) -> Request {
        self.request
    }

    /// Build a `Request`, which can be inspected, modified and executed with
    /// `Client::execute()`.
    ///
    /// This is similar to [`RequestBuilder::build()`], but also returns the
    /// embedded `Client`.
    pub fn build_split(self) -> (Client, Request) {
        (self.client, self.request)
    }

    /// Constructs the Request and sends it to the target URL, returning a
    /// future Response.
    pub async fn send(self) -> Result<Response> {
        self.client.execute(self.request).await
    }
}
