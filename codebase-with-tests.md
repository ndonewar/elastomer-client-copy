# .ruby-version

```
3.2.2

```

# docker/compose.yaml

```yaml
version: "3"

services:
  elasticsearch8.13:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.2
    container_name: es8.13
    profiles: ["es8", "all"]
    environment:
      - cluster.name=elastomer8.13
      - bootstrap.memory_lock=true
      - discovery.type=single-node
      - xpack.security.enabled=false
      - xpack.watcher.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    mem_limit: 2g
    cap_add:
      - IPC_LOCK
    volumes:
      - esrepos8:/usr/share/elasticsearch/repos
      - ./elasticsearch8plus.yml:/usr/share/elasticsearch/config/elasticsearch.yml
    ports:
      - 127.0.0.1:${ES_8_PORT:-9208}:9200
  
  elasticsearch5.6:
    image: docker.elastic.co/elasticsearch/elasticsearch:5.6.4
    container_name: es5.6
    profiles: ["es5", "all"]
    environment:
      - cluster.name=elastomer5.6
      - bootstrap.memory_lock=true
      - discovery.type=single-node
      - xpack.monitoring.enabled=false
      - xpack.security.enabled=false
      - xpack.watcher.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    mem_limit: 1g
    cap_add:
      - IPC_LOCK
    volumes:
      - esrepos5:/usr/share/elasticsearch/repos
      - ./elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
    ports:
      - 127.0.0.1:${ES_5_PORT:-9205}:9200

volumes:
  esrepos8:
    driver: local
    driver_opts:
      device: tmpfs
      type: tmpfs
      o: size=100m,uid=102,gid=102
  esrepos5:
    driver: local
    driver_opts:
      device: tmpfs
      type: tmpfs
      o: size=100m,uid=102,gid=102

```

# docker/elasticsearch.yml

```yml
cluster.name: "docker-cluster"

network.host: 0.0.0.0

discovery.zen.minimum_master_nodes: 1

path:
  data: /usr/share/elasticsearch/data
  logs: /usr/share/elasticsearch/logs
  repo: /usr/share/elasticsearch/repos

transport.tcp.port: 9300
http.port: 9200
http.max_content_length: 50mb


```

# docker/elasticsearch8plus.yml

```yml
cluster.name: "docker-cluster"

network.host: 0.0.0.0

path:
  data: /usr/share/elasticsearch/data
  logs: /usr/share/elasticsearch/logs
  repo: /usr/share/elasticsearch/repos

transport.port: 9300
http.port: 9200
http.max_content_length: 50mb
ingest.geoip.downloader.enabled: false

```

# elastomer-client.gemspec

```gemspec
# coding: utf-8
# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "elastomer_client/version"

Gem::Specification.new do |spec|
  spec.name          = "elastomer-client"
  spec.version       = ElastomerClient::VERSION
  spec.authors       = ["Tim Pease", "Grant Rodgers"]
  spec.email         = ["tim.pease@github.com", "grant.rodgers@github.com"]
  spec.summary       = %q{A library for interacting with Elasticsearch}
  spec.description   = %q{ElastomerClient is a low level API client for the
                          Elasticsearch HTTP interface.}
  spec.homepage      = "https://github.com/github/elastomer-client"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "addressable", "~> 2.5"
  spec.add_dependency "faraday",     ">= 0.17"
  spec.add_dependency "faraday_middleware", ">= 0.14"
  spec.add_dependency "multi_json",  "~> 1.12"
  spec.add_dependency "semantic",    "~> 1.6"
end

```

# Gemfile

```
# frozen_string_literal: true

source "https://rubygems.org"

gemspec

group :development do
  gem "activesupport", ">= 7.0"
  gem "bundler", "~> 2.0"
  gem "debug", "~> 1.7"
  gem "minitest", "~> 5.17"
  gem "minitest-focus", "~> 1.3"
  gem "rake"
  gem "rubocop", "~> 1.63.0"
  gem "rubocop-github", "~> 0.20.0"
  gem "rubocop-minitest", "~> 0.35.0"
  gem "rubocop-performance", "~> 1.21.0"
  gem "rubocop-rake", "~> 0.6.0"
  gem "simplecov", require: false
  gem "spy", "~> 1.0"
  gem "webmock", "~> 3.5"
end

```

# lib/elastomer_client/client.rb

```rb
# frozen_string_literal: true

require "addressable/template"
require "faraday"
require "faraday_middleware"
require "multi_json"
require "semantic"
require "zlib"

require "elastomer_client/version"
require "elastomer_client/version_support"

module ElastomerClient

  class Client
    IVAR_BLACK_LIST = [:@basic_auth, :@token_auth]
    IVAR_NOISY_LIST = [:@api_spec, :@cluster, :@connection]

    MAX_REQUEST_SIZE = 2**20 * 250  # 250 MB

    # Create a new client that can be used to make HTTP requests to the
    # Elasticsearch server.
    #
    # see lib/elastomer_client/client/errors.rb#L92-L94
    #
    # Method params:
    #   :host - the host as a String
    #   :port - the port number of the server
    #   :url  - the URL as a String (overrides :host and :port)
    #   :read_timeout - the timeout in seconds when reading from an HTTP connection
    #   :open_timeout - the timeout in seconds when opening an HTTP connection
    #   :adapter      - the Faraday adapter to use (defaults to :excon)
    #   :opaque_id    - set to `true` to use the 'X-Opaque-Id' request header
    #   :max_request_size - the maximum allowed request size in bytes (defaults to 250 MB)
    #   :strict_params    - set to `true` to raise exceptions when invalid request params are used
    #   :es_version       - set to the Elasticsearch version (example: "5.6.6") to avoid an HTTP request to get the version.
    #   :compress_body    - set to true to enable request body compression (default: false)
    #   :compression      - The compression level (0-9) when request body compression is enabled (default: Zlib::DEFAULT_COMPRESSION)
    #   :basic_auth       - a Hash containing basic authentication :username and :password values to use on connections
    #   :token_auth       - an authentication token as a String to use on connections (overrides :basic_auth)
    #
    def initialize(host: "localhost", port: 9200, url: nil,
                   read_timeout: 5, open_timeout: 2, opaque_id: false, adapter: Faraday.default_adapter, max_request_size: MAX_REQUEST_SIZE,
                   strict_params: false, es_version: nil, compress_body: false, compression: Zlib::DEFAULT_COMPRESSION,
                   basic_auth: nil, token_auth: nil, &block)

      @url = url || "http://#{host}:#{port}"

      uri = Addressable::URI.parse @url
      @host = uri.host
      @port = uri.port

      @read_timeout     = read_timeout
      @open_timeout     = open_timeout
      @adapter          = adapter
      @opaque_id        = opaque_id
      @max_request_size = max_request_size
      @strict_params    = strict_params
      @es_version       = es_version
      @compress_body    = compress_body
      @compression      = compression
      @basic_auth       = basic_auth
      @token_auth       = token_auth
      @connection_block = block
    end

    attr_reader :host, :port, :url
    attr_reader :read_timeout, :open_timeout
    attr_reader :max_request_size
    attr_reader :strict_params
    attr_reader :es_version
    attr_reader :compress_body
    attr_reader :compression
    alias :strict_params? :strict_params

    # Returns a duplicate of this Client connection configured in the exact same
    # fashion.
    def dup
      self.class.new \
          url:,
          read_timeout:,
          open_timeout:,
          adapter:          @adapter,
          opaque_id:        @opaque_id,
          max_request_size:,
          basic_auth:       @basic_auth,
          token_auth:       @token_auth
    end

    # Returns true if the server is available; returns false otherwise.
    def ping
      response = head "/", action: "cluster.ping"
      response.success?
    rescue StandardError
      false
    end
    alias_method :available?, :ping

    # Returns the version String of the attached Elasticsearch instance.
    def version
      return es_version unless es_version.nil?

      @version ||= begin
        response = get "/"
        response.body.dig("version", "number")
      end
    end

    # Returns a Semantic::Version for the attached Elasticsearch instance.
    # See https://rubygems.org/gems/semantic
    def semantic_version
      Semantic::Version.new(version)
    end

    # Returns the information Hash from the attached Elasticsearch instance.
    def info
      response = get "/", action: "cluster.info"
      response.body
    end

    # Returns the ApiSpec for the specific version of Elasticsearch that this
    # Client is connected to.
    def api_spec
      @api_spec ||= RestApiSpec.api_spec(version)
    end

    # Internal: Provides access to the Faraday::Connection used by this client
    # for all requests to the server.
    #
    # Returns a Faraday::Connection
    def connection
      @connection ||= Faraday.new(url) do |conn|
        conn.response(:parse_json)
        # Request compressed responses from ES and decompress them
        conn.use(:gzip)
        conn.request(:encode_json)
        conn.request(:limit_size, max_request_size:) if max_request_size
        conn.request(:elastomer_compress, compression:) if compress_body

        conn.options[:timeout]      = read_timeout
        conn.options[:open_timeout] = open_timeout

        if token_auth?
          conn.token_auth(@token_auth)
        elsif basic_auth?
          conn.basic_auth(@basic_auth[:username], @basic_auth[:password])
        end

        @connection_block&.call(conn)

        conn.request(:opaque_id) if @opaque_id

        if @adapter.is_a?(Array)
          conn.adapter(*@adapter)
        else
          conn.adapter(@adapter)
        end
      end
    end

    # Internal: Reset the client by removing the current Faraday::Connection. A
    # new connection will be established on the next request.
    #
    # Returns this Client instance.
    def reset!
      @connection = nil
      self
    end

    # Internal: Sends an HTTP HEAD request to the server.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Returns a Faraday::Response
    def head(path, params = {})
      request :head, path, params
    end

    # Internal: Sends an HTTP GET request to the server.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Returns a Faraday::Response
    # Raises an ElastomerClient::Client::Error on 4XX and 5XX responses
    def get(path, params = {})
      request :get, path, params
    end

    # Internal: Sends an HTTP PUT request to the server.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Returns a Faraday::Response
    # Raises an ElastomerClient::Client::Error on 4XX and 5XX responses
    def put(path, params = {})
      request :put, path, params
    end

    # Internal: Sends an HTTP POST request to the server.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Returns a Faraday::Response
    # Raises an ElastomerClient::Client::Error on 4XX and 5XX responses
    def post(path, params = {})
      request :post, path, params
    end

    # Internal: Sends an HTTP DELETE request to the server.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Returns a Faraday::Response
    # Raises an ElastomerClient::Client::Error on 4XX and 5XX responses
    def delete(path, params = {})
      request :delete, path, params
    end

    # Internal: Sends an HTTP request to the server. If the `params` Hash
    # contains a :body key, it will be deleted from the Hash and the value
    # will be used as the body of the request.
    #
    # method - The HTTP method to send [:head, :get, :put, :post, :delete]
    # path   - The path as a String
    # params - Parameters Hash
    #   :body         - Will be used as the request body
    #   :read_timeout - Optional read timeout (in seconds) for the request
    #
    # Returns a Faraday::Response
    # Raises an ElastomerClient::Client::Error on 4XX and 5XX responses
    def request(method, path, params)
      read_timeout = params.delete(:read_timeout)
      body = extract_body(params)
      path = expand_path(path, params)

      instrument(path, body, params) do
        begin
          response =
            case method
            when :head
              connection.head(path) { |req| req.options[:timeout] = read_timeout if read_timeout }

            when :get
              connection.get(path) { |req|
                req.body = body if body
                req.options[:timeout] = read_timeout if read_timeout
              }

            when :put
              connection.put(path, body) { |req| req.options[:timeout] = read_timeout if read_timeout }

            when :post
              connection.post(path, body) { |req| req.options[:timeout] = read_timeout if read_timeout }

            when :delete
              connection.delete(path) { |req|
                req.body = body if body
                req.options[:timeout] = read_timeout if read_timeout
              }

            else
              raise ArgumentError, "unknown HTTP request method: #{method.inspect}"
            end

          handle_errors response

        # wrap Faraday errors with appropriate ElastomerClient::Client error classes
        rescue Faraday::Error => boom
          error = wrap_faraday_error(boom, method, path)
          raise error
        rescue OpaqueIdError => boom
          reset!
          raise boom
        end
      end
    end
    # rubocop:enable Metrics/MethodLength

    # Internal: Returns a new ElastomerClient::Client error that wraps the given
    # Faraday error. A generic Error is returned if we cannot wrap the given
    # Faraday error.
    #
    #   error  - The Faraday error
    #   method - The request method
    #   path   - The request path
    #
    def wrap_faraday_error(error, method, path)
      error_name  = error.class.name.split("::").last
      error_class = ElastomerClient::Client.const_get(error_name) rescue ElastomerClient::Client::Error
      error_class.new(error, method.upcase, path)
    end

    # Internal: Extract the :body from the params Hash and convert it to a
    # JSON String format. If the params Hash does not contain a :body then no
    # action is taken and `nil` is returned.
    #
    # If a :body is present and is a String then it is assumed to a JSON String
    # and returned "as is".
    #
    # If a :body is present and is an Array then we join the values together
    # with newlines and append a trailing newline. This is a special case for
    # dealing with ES `bulk` imports and `multi_search` methods.
    #
    # Otherwise we convert the :body to a JSON string and return.
    #
    # params - Parameters Hash
    #
    # Returns the request body as a String or `nil` if no :body is present
    def extract_body(params)
      body = params.delete :body
      return if body.nil?

      body =
        case body
        when String
          body
        when Array
          body << nil unless body.last.nil?
          body.join "\n"
        else
          MultiJson.dump body
        end

      # Prevent excon from changing the encoding (see https://github.com/github/elastomer-client/issues/138)
      body.freeze
    end

    # Internal: Apply path expansions to the `path` and append query
    # parameters to the `path`. We are using an Addressable::Template to
    # replace '{expansion}' fields found in the path with the values extracted
    # from the `params` Hash. Any remaining elements in the `params` hash are
    # treated as query parameters and appended to the end of the path.
    #
    # path   - The path as a String
    # params - Parameters Hash
    #
    # Examples
    #
    #   expand_path('/foo{/bar}', {bar: 'hello', q: 'what', p: 2})
    #   #=> '/foo/hello?q=what&p=2'
    #
    #   expand_path('/foo{/bar}{/baz}', {baz: 'no bar'}
    #   #=> '/foo/no%20bar'
    #
    # Returns an Addressable::Uri
    def expand_path(path, params)
      template = Addressable::Template.new path

      expansions = {}
      query_values = params.dup
      query_values.delete :action
      query_values.delete :context

      rest_api = query_values.delete :rest_api

      template.keys.map(&:to_sym).each do |key|
        value = query_values.delete key
        value = assert_param_presence(value, key) unless path =~ /{\/#{key}}/ && value.nil?
        expansions[key] = value
      end

      if rest_api
        query_values = if strict_params?
                         api_spec.validate_params!(api: rest_api, params: query_values)
        else
          api_spec.select_params(api: rest_api, from: query_values)
        end
      end

      uri = template.expand(expansions)
      query_values.transform_keys!(&:to_s)
      uri.query_values = (uri.query_values || {}).merge(query_values) unless query_values.empty?

      uri.to_s
    end

    # Internal: A noop method that simply yields to the block. This method
    # will be replaced when the 'elastomer_client/notifications' module is included.
    #
    # path   - The full request path as a String
    # body   - The request body as a String or `nil`
    # params - The request params Hash
    # block  - The block that will be instrumented
    #
    # Returns the response from the block
    def instrument(path, body, params)
      yield
    end

    # Internal: Inspect the Faraday::Response and raise an error if the status
    # is in the 5XX range or if the response body contains an 'error' field.
    # In the latter case, the value of the 'error' field becomes our exception
    # message. In the absence of an 'error' field the response body is used
    # as the exception message.
    #
    # The raised exception will contain the response object.
    #
    # response - The Faraday::Response object.
    #
    # Returns the response.
    # Raises an ElastomerClient::Client::Error on 500 responses or responses
    # containing and 'error' field.
    def handle_errors(response)
      raise ServerError, response if response.status >= 500

      if response.body.is_a?(Hash) && (error = response.body["error"])
        root_cause = Array(error["root_cause"]).first || error
        case root_cause["type"]
        when "index_not_found_exception"; raise IndexNotFoundError, response
        when "illegal_argument_exception"; raise IllegalArgument, response
        when "es_rejected_execution_exception"; raise RejectedExecutionError, response
        # Elasticsearch 2.x.x root_cause type for document already existing
        when "document_already_exists_exception"; raise DocumentAlreadyExistsError, response
        # Elasticsearch 5.x.x root_cause type for document already existing
        when "version_conflict_engine_exception"; raise DocumentAlreadyExistsError, response
        when "query_shard_exception", "parsing_exception"; raise QueryParsingError, response
        end

        raise RequestError, response
      end

      response
    end

    # Internal: Ensure that the parameter has a valid value. Strings, Symbols,
    # Numerics, and Arrays of those things are valid. Things like `nil`
    # and empty strings are right out. This method also performs a little
    # formating on the parameter:
    #
    # * leading and trailing whitespace is removed
    # * arrays are flattend
    # * and then joined into a String
    # * numerics are converted to their string equivalents
    #
    # param - The param Object to validate
    # name  - Optional param name as a String (used in exception messages)
    #
    # Returns the validated param as a String.
    # Raises an ArgumentError if the param is not valid.
    def assert_param_presence(param, name = "input value")
      case param
      when String, Symbol, Numeric
        param = param.to_s.strip
        raise ArgumentError, "#{name} cannot be blank: #{param.inspect}" if param =~ /\A\s*\z/
        param

      when Array
        param.flatten.map { |item| assert_param_presence(item, name) }.join(",")

      when nil
        raise ArgumentError, "#{name} cannot be nil"

      else
        raise ArgumentError, "#{name} is invalid: #{param.inspect}"
      end
    end

    def version_support
      @version_support ||= VersionSupport.new(version)
    end

    def inspect
      public_vars = self.instance_variables.reject do |var|
        IVAR_NOISY_LIST.include?(var)
      end.map do |var|
        "#{var}=#{IVAR_BLACK_LIST.include?(var) ? "[FILTERED]" : instance_variable_get(var).inspect}"
      end.join(", ")
      "<##{self.class}:#{self.object_id.to_s(16)} #{public_vars}>"
    end

    private

    def token_auth?
      present_for_auth?(@token_auth)
    end

    def basic_auth?
      @basic_auth.is_a?(Hash) &&
        present_for_auth?(@basic_auth[:username]) &&
        present_for_auth?(@basic_auth[:password])
    end

    # Cheap implementation of ActiveSupport's Object#present?
    def present_for_auth?(object)
      object.respond_to?(:empty?) ? !object.empty? : !!object
    end
  end  # Client
end  # ElastomerClient

# require all files in the `client` sub-directory
Dir.glob(File.expand_path("../client/*.rb", __FILE__)).each { |fn| require fn }

# require all files in the `middleware` sub-directory
Dir.glob(File.expand_path("../middleware/*.rb", __FILE__)).each { |fn| require fn }

```

# lib/elastomer_client/client/bulk.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # The `bulk` method can be used in two ways. Without a block the method
    # will perform an API call, and it requires a bulk request body and
    # optional request parameters. If given a block, the method will use a
    # Bulk instance to assemble the operations called in the block into a
    # bulk request and dispatch it at the end of the block.
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
    #
    # body   - Request body as a String (required if a block is _not_ given)
    # params - Optional request parameters as a Hash
    #   :request_size - Optional maximum request size in bytes
    #   :action_count - Optional maximum action size
    # block  - Passed to a Bulk instance which assembles the operations
    #          into one or more bulk requests.
    #
    # Examples
    #
    #   bulk(request_body, :index => 'default-index')
    #
    #   bulk(:index => 'default-index') do |b|
    #     b.index(document1)
    #     b.index(document2, :_type => 'default-type')
    #     b.delete(document3)
    #     ...
    #   end
    #
    # Returns the response body as a Hash
    def bulk(body = nil, params = nil)
      if block_given?
        params, body = (body || {}), nil
        yield bulk_obj = Bulk.new(self, params)
        bulk_obj.call

      else
        raise "bulk request body cannot be nil" if body.nil?
        params ||= {}
        updated_params = params.merge(body:, action: "bulk", rest_api: "bulk")
        updated_params.delete(:type) if version_support.es_version_8_plus?

        response = self.post "{/index}{/type}/_bulk", updated_params
        response.body
      end
    end

    # Stream bulk actions from an Enumerator.
    #
    # Examples
    #
    #   ops = [
    #     [:index, document1, {:_type => "foo", :_id => 1}],
    #     [:create, document2],
    #     [:delete, {:_type => "bar", :_id => 42}]
    #   ]
    #   bulk_stream_responses(ops, :index => 'default-index').each do |response|
    #     puts response
    #   end
    #
    # Returns an Enumerator of responses.
    def bulk_stream_responses(ops, params = {})
      bulk_obj = Bulk.new(self, params)

      Enumerator.new do |yielder|
        ops.each do |action, *args|
          response = bulk_obj.send(action, *args)
          yielder.yield response unless response.nil?
        end

        response = bulk_obj.call
        yielder.yield response unless response.nil?
      end
    end

    # Internal: Determine whether or not a response item has an HTTP status code
    # in the range 200 to 299.
    #
    # item - The bulk response item
    #
    # Returns a boolean
    def is_ok?(item)
      item.values.first["status"].between?(200, 299)
    end

    # Stream bulk actions from an Enumerator and passes the response items to
    # the given block.
    #
    # Examples
    #
    #   ops = [
    #     [:index, document1, {:_type => "foo", :_id => 1}],
    #     [:create, document2],
    #     [:delete, {:_type => "bar", :_id => 42}]
    #   ]
    #   bulk_stream_items(ops, :index => 'default-index') do |item|
    #     puts item
    #   end
    #
    #   # return value:
    #   # {
    #   #   "took" => 256,
    #   #   "errors" => false,
    #   #   "success" => 3,
    #   #   "failure" => 0
    #   # }
    #
    #   # sample response item for ES5:
    #   # {
    #   #   "delete": {
    #   #     "_index": "foo",
    #   #     "_type": "bar",
    #   #     "_id": "42",
    #   #     "_version": 3,
    #   #     "status": 200,
    #   #     "found": true
    #   #   }
    #   # }
    #
    #   # sample response item for ES8:
    #   # {
    #   #   "delete": {
    #   #     "_index": "foo",
    #   #     "_id": "42",
    #   #     "_version": 3,
    #   #     "status": 200,
    #   #     "result": "deleted"
    #   #   }
    #   # }
    #
    # Returns a Hash of stats about items from the responses.
    def bulk_stream_items(ops, params = {})
      stats = {
        "took" => 0,
        "errors" => false,
        "success" => 0,
        "failure" => 0
      }

      bulk_stream_responses(ops, params).each do |response|
        stats["took"] += response["took"]
        stats["errors"] |= response["errors"]

        response["items"].each do |item|
          if is_ok?(item)
            stats["success"] += 1
          else
            stats["failure"] += 1
          end
          yield item
        end
      end

      stats
    end

    # The Bulk class provides some abstractions and helper methods for working
    # with the Elasticsearch bulk API command. Instances of the Bulk class
    # accumulate indexing and delete operations and then issue a single bulk
    # API request to Elasticsearch. Those operations are then executed by the
    # cluster.
    #
    # A maximum request size can be set. As soon as the size of the request
    # body hits this threshold, a bulk request will be made to the search
    # cluster. This happens as operations are added.
    #
    # Additionally, a maximum action count can be set. As soon as the number
    # of actions equals the action count, a bulk request will be made.
    #
    # You can also use the `call` method explicitly to send a bulk request
    # immediately.
    #
    class Bulk
      DEFAULT_REQUEST_SIZE = 2**20 * 10  # 10 MB

      # Create a new bulk client for handling some of the details of
      # accumulating documents to index and then formatting them properly for
      # the bulk API command.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # params - Parameters Hash to pass to the Client#bulk method
      #   :request_size - the maximum request size in bytes
      #   :action_count - the maximum number of actions
      def initialize(client, params = {})
        @client  = client
        @params  = params

        @actions = []
        @current_request_size = 0
        @current_action_count = 0
        self.request_size = params.delete(:request_size) || DEFAULT_REQUEST_SIZE
        self.action_count = params.delete(:action_count)
      end

      attr_reader :client, :request_size, :action_count

      # Set the request size in bytes. If the value is nil, then request size
      # limiting will not be used and a request will only be made when the call
      # method is called. It is up to the user to ensure that the request does
      # not exceed Elasticsearch request size limits.
      #
      # If the value is a number greater than zero, then actions will be
      # buffered until the request size is met or exceeded. When this happens a
      # bulk request is issued, queued actions are cleared, and the response
      # from Elasticsearch is returned.
      def request_size=(value)
        if value.nil?
          @request_size = nil
        else
          value = value.to_i
          value = nil if value <= 0
          value = client.max_request_size if value > client.max_request_size
          @request_size = value
        end
      end

      # Set the action count. If the value is nil, then action count limiting
      # will not be used and a request will only be made when the call method
      # is called. It is up to the user to ensure that the request does not
      # exceed Elasticsearch request size limits.
      #
      # If the value is a number greater than zero, then actions will be
      # buffered until the action count is met. When this happens a bulk
      # request is issued, queued actions are cleared, and the response from
      # Elasticsearch is returned.
      def action_count=(value)
        if value.nil?
          @action_count = nil
        else
          @action_count = value.to_i <= 0 ? nil : value.to_i
        end
      end

      # Add an index action to the list of bulk actions to be performed when
      # the bulk API call is made. Parameters can be provided in the
      # parameters hash (underscore prefix optional) or in the document
      # hash (underscore prefix required).
      #
      # document - The document to index as a Hash or JSON encoded String
      # params   - Parameters for the index action (as a Hash) (optional)
      #
      # Examples
      #   index({"foo" => "bar"}, {:_id => 1, :_type => "foo"}
      #   index({"foo" => "bar"}, {:id => 1, :type => "foo"}
      #   index("foo" => "bar", "_id" => 1, "_type" => "foo")
      #
      # Returns the response from the bulk call if one was made or nil.
      def index(document, params = {})
        params = prepare_params(document, params)
        add_to_actions({index: params}, document)
      end

      # Add a create action to the list of bulk actions to be performed when
      # the bulk API call is made. Parameters can be provided in the
      # parameters hash (underscore prefix optional) or in the document
      # hash (underscore prefix required).
      #
      # document - The document to create as a Hash or JSON encoded String
      # params   - Parameters for the create action (as a Hash) (optional)
      #
      # Examples
      #   create({"foo" => "bar"}, {:_id => 1}
      #   create({"foo" => "bar"}, {:id => 1}
      #   create("foo" => "bar", "_id" => 1)
      #
      # Returns the response from the bulk call if one was made or nil.
      def create(document, params)
        params = prepare_params(document, params)
        add_to_actions({create: params}, document)
      end

      # Add an update action to the list of bulk actions to be performed when
      # the bulk API call is made. Parameters can be provided in the parameters
      # hash (underscore prefix optional) or in the document hash (underscore
      # prefix required).
      #
      # document - The document to update as a Hash or JSON encoded String
      # params   - Parameters for the update action (as a Hash) (optional)
      #
      # Examples
      #   update({"doc" => {"foo" => "bar"}}, {:_id => 1})
      #   update({"doc" => {"foo" => "bar"}}, {:id => 1})
      #   update({"doc" => {"foo" => "bar"}}, "_id" => 1)
      #
      # Returns the response from the bulk call if one was made or nil.
      def update(document, params)
        params = prepare_params(document, params)
        add_to_actions({update: params}, document)
      end

      # Add a delete action to the list of bulk actions to be performed when
      # the bulk API call is made.
      #
      # params - Parameters for the delete action (as a Hash)
      #
      # Examples
      #   delete(:_id => 1, :_type => 'foo')
      #
      # Returns the response from the bulk call if one was made or nil.
      def delete(params)
        params = prepare_params(nil, params)
        add_to_actions({delete: params})
      end

      # Immediately execute a bulk API call with the currently accumulated
      # actions. The accumulated actions list will be cleared after the call
      # has been made.
      #
      # If the accumulated actions list is empty then no action is taken.
      #
      # Returns the response body Hash.
      def call
        return nil if @actions.empty?

        body = @actions.join("\n") + "\n"
        client.bulk(body, @params)
      ensure
        @current_request_size = 0
        @current_action_count = 0
        @actions.clear
      end

      SPECIAL_KEYS = %w[id type index version version_type routing parent consistency refresh retry_on_conflict]
      UNPREFIXED_SPECIAL_KEYS = %w[parent retry_on_conflict routing version version_type]

      # Internal: convert special key parameters to their wire representation
      # and apply any override document parameters.
      def prepare_params(document, params)
        params = convert_special_keys(params)

        params.delete(:_id) if params[:_id].nil? || params[:_id].to_s.empty?
        params.delete("_id") if params["_id"].nil? || params["_id"].to_s.empty?

        if client.version_support.es_version_8_plus?
          params.delete(:_type)
          params.delete("_type")
        end

        params
      end

      # Internal: Convert incoming Ruby symbol keys to their special underscore
      # versions. Maintains API compaibility with the `Docs` API for `index`,
      # `create`, `update` and `delete`.
      #
      # :id -> :_id
      # 'id' -> '_id'
      #
      # params - Hash.
      #
      # Returns a new params Hash with the special keys replaced.
      def convert_special_keys(params)
        new_params = params.dup

        SPECIAL_KEYS.each do |key|
          omit_prefix = (
            client.version_support.es_version_8_plus? &&
            UNPREFIXED_SPECIAL_KEYS.include?(key)
          )

          prefixed_key = "_" + key
          converted_key = (omit_prefix ? "" : "_") + key

          if new_params.key?(prefixed_key)
            new_params[converted_key] = new_params.delete(prefixed_key)
          end

          if new_params.key?(prefixed_key.to_sym)
            new_params[converted_key.to_sym] = new_params.delete(prefixed_key.to_sym)
          end

          if new_params.key?(key)
            new_params[converted_key] = new_params.delete(key)
          end

          if new_params.key?(key.to_sym)
            new_params[converted_key.to_sym] = new_params.delete(key.to_sym)
          end
        end

        new_params
      end

      # Internal: Add the given `action` to the list of actions that will be
      # performed by this bulk request. An optional `document` can also be
      # given.
      #
      # If the total size of the accumulated actions meets our desired request
      # size, then a bulk API call will be performed. After the call the
      # actions list is cleared and we'll start accumulating actions again.
      #
      # action   - The bulk action (as a Hash) to perform
      # document - Optional document for the action as a Hash or JSON encoded String
      #
      # Returns the response from the bulk call if one was made or nil.
      # Raises RequestSizeError if the given action is larger than the
      #        configured requst size or the client.max_request_size
      def add_to_actions(action, document = nil)
        action = MultiJson.dump(action)
        size = action.bytesize

        if document
          document = MultiJson.dump(document) unless document.is_a?(String)
          size += document.bytesize
        end

        check_action_size!(size)

        response = nil
        begin
          response = call if ready_to_send?(size)
        # rubocop:disable Lint/UselessRescue
        rescue StandardError => err
          raise err
        ensure
          @actions << action
          @actions << document unless document.nil?
          @current_request_size += size
          @current_action_count += 1
        end

        response
      end

      # Internal: Determines if adding `size` more bytes and one more action
      # will bring the current bulk request over the `request_size` limit or the
      # `action_count` limit. If this method returns true, then it is time to
      # dispatch the bulk request.
      #
      # Returns `true` of `false`
      def ready_to_send?(size)
        total_request_size = @current_request_size + size
        total_action_count = @current_action_count + 1

        (request_size && total_request_size >= request_size) ||
        (action_count && total_action_count >  action_count)
      end

      # Internal: Raises a RequestSizeError if the given size is larger than
      # the configured client.max_request_size
      def check_action_size!(size)
        return unless size > client.max_request_size
        raise RequestSizeError, "Bulk action of size `#{size}` exceeds the maximum requst size: #{client.max_request_size}"
      end

    end
  end
end

```

# lib/elastomer_client/client/cluster.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Returns a Cluster instance.
    def cluster
      @cluster ||= Cluster.new self
    end

    class Cluster

      # Create a new cluster client for making API requests that pertain to
      # the cluster health and management.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      #
      def initialize(client)
        @client = client
      end

      attr_reader :client

      # Simple status on the health of the cluster. The API can also be executed
      # against one or more indices to get just the specified indices health.
      #
      # params - Parameters Hash
      #   :index - a single index name or an Array of index names
      #   :level - one of "cluster", "indices", or "shards"
      #   :wait_for_status - one of "green", "yellow", or "red"
      #   :wait_for_relocating_shards - a number controlling to how many relocating shards to wait for
      #   :wait_for_nodes - the request waits until the specified number N of nodes is available
      #   :timeout - how long to wait [default is "30s"]
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html
      #
      # Returns the response as a Hash
      def health(params = {})
        response = client.get "/_cluster/health{/index}", params.merge(action: "cluster.health", rest_api: "cluster.health")
        response.body
      end

      # Comprehensive state information of the whole cluster. For 1.x metric
      # and index filtering, use the :metrics and :indices parameter keys.
      #
      # The list of available metrics are:
      #   version, master_node, nodes, routing_table, metadata, blocks
      #
      # params - Parameters Hash
      #   :metrics - list of metrics to select as an Array
      #   :indices - a single index name or an Array of index names
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-state.html
      #
      # Returns the response as a Hash
      def state(params = {})
        response = client.get "/_cluster/state{/metrics}{/indices}", params.merge(action: "cluster.state", rest_api: "cluster.state")
        response.body
      end

      # Retrieve statistics from a cluster wide perspective. The API returns
      # basic index metrics (shard numbers, store size, memory usage) and
      # information about the current nodes that form the cluster (number,
      # roles, os, jvm versions, memory usage, cpu and installed plugins).
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-stats.html
      #
      # Returns the response as a Hash
      def stats(params = {})
        response = client.get "/_cluster/stats", params.merge(action: "cluster.stats", rest_api: "cluster.stats")
        response.body
      end

      # Returns a list of any cluster-level changes (e.g. create index, update
      # mapping, allocate or fail shard) which have not yet been executed.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-pending.html
      #
      # Returns the response as a Hash
      def pending_tasks(params = {})
        response = client.get "/_cluster/pending_tasks", params.merge(action: "cluster.pending_tasks", rest_api: "cluster.pending_tasks")
        response.body
      end

      # Returns `true` if there items in the pending task list. Returns `false`
      # if the pending task list is empty. Returns `nil` if the response body
      # does not contain the "tasks" field.
      def pending_tasks?
        hash = pending_tasks
        return nil unless hash.key? "tasks" # rubocop:disable Style/ReturnNilInPredicateMethodDefinition
        hash["tasks"].length > 0
      end

      # Cluster wide settings that have been modified via the update API.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-update-settings.html
      #
      # Returns the response as a Hash
      def get_settings(params = {})
        response = client.get "/_cluster/settings", params.merge(action: "cluster.get_settings", rest_api: "cluster.get_settings")
        response.body
      end
      alias_method :settings, :get_settings

      # Update cluster wide specific settings. Settings updated can either be
      # persistent (applied cross restarts) or transient (will not survive a
      # full cluster restart).
      #
      # body   - The new settings as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-update-settings.html
      #
      # Returns the response as a Hash
      def update_settings(body, params = {})
        response = client.put "/_cluster/settings", params.merge(body:, action: "cluster.update_settings", rest_api: "cluster.put_settings")
        response.body
      end

      # Explicitly execute a cluster reroute allocation command. For example,
      # a shard can be moved from one node to another explicitly, an
      # allocation can be canceled, or an unassigned shard can be explicitly
      # allocated on a specific node.
      #
      # commands - A command Hash or an Array of command Hashes
      # params   - Parameters Hash
      #
      # Examples
      #
      #   reroute(move: { index: 'test', shard: 0, from_node: 'node1', to_node: 'node2' })
      #
      #   reroute([
      #     { move:     { index: 'test', shard: 0, from_node: 'node1', to_node: 'node2' }},
      #     { allocate: { index: 'test', shard: 1, node: 'node3' }}
      #   ])
      #
      #   reroute(commands: [
      #     { move:     { index: 'test', shard: 0, from_node: 'node1', to_node: 'node2' }},
      #     { allocate: { index: 'test', shard: 1, node: 'node3' }}
      #   ])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-reroute.html
      #
      # Returns the response as a Hash
      def reroute(commands, params = {})
        if commands.is_a?(Hash) && commands.key?(:commands)
          body = commands
        elsif commands.is_a?(Hash)
          # Array() on a Hash does not do what you think it does - that is why
          # we are explicitly wrapping the Hash via [commands] here.
          body = {commands: [commands]}
        else
          body = {commands: Array(commands)}
        end

        response = client.post "/_cluster/reroute", params.merge(body:, action: "cluster.reroute", rest_api: "cluster.reroute")
        response.body
      end

      # Retrieve the current aliases. An :index name can be given (or an
      # array of index names) to get just the aliases for those indexes. You
      # can also use the alias name here since it is acting the part of an
      # index.
      #
      # params - Parameters Hash
      #   :index - an index name or Array of index names
      #   :name  - an alias name or Array of alias names
      #
      # Examples
      #
      #   get_aliases
      #   get_aliases( index: 'users' )
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def get_aliases(params = {})
        response = client.get "{/index}/_alias{/name}", params.merge(action: "cluster.get_aliases", rest_api: "indices.get_alias")
        response.body
      end
      alias_method :aliases, :get_aliases

      # Perform an aliases action on the cluster. We are just a teensy bit
      # clever here in that a single action can be given or an array of
      # actions. This API method will wrap the request in the appropriate
      # {actions: [...]} body construct.
      #
      # actions - An action Hash or an Array of action Hashes
      # params  - Parameters Hash
      #
      # Examples
      #
      #   update_aliases(add: { index: 'users-1', alias: 'users' })
      #
      #   update_aliases([
      #     { remove: { index: 'users-1', alias: 'users' }},
      #     { add:    { index: 'users-2', alias: 'users' }}
      #   ])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def update_aliases(actions, params = {})
        if actions.is_a?(Hash) && actions.key?(:actions)
          body = actions
        elsif actions.is_a?(Hash)
          # Array() on a Hash does not do what you think it does - that is why
          # we are explicitly wrapping the Hash via [actions] here.
          body = {actions: [actions]}
        else
          body = {actions: Array(actions)}
        end

        response = client.post "/_aliases", params.merge(body:, action: "cluster.update_aliases", rest_api: "indices.update_aliases")
        response.body
      end

      # List all templates currently defined. This is just a convenience method
      # around the `state` call that extracts and returns the templates section.
      #
      # Returns the template definitions as a Hash
      def templates
        state(metrics: "metadata").dig("metadata", "templates")
      end

      # List all indices currently defined. This is just a convenience method
      # around the `state` call that extracts and returns the indices section.
      #
      # Returns the indices definitions as a Hash
      def indices
        state(metrics: "metadata").dig("metadata", "indices")
      end

      # List all nodes currently part of the cluster. This is just a convenience
      # method around the `state` call that extracts and returns the nodes
      # section.
      #
      # Returns the nodes definitions as a Hash
      def nodes
        state(metrics: "nodes").dig("nodes")
      end

    end
  end
end

```

# lib/elastomer_client/client/delete_by_query.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client
    # Execute delete_by_query using the native _delete_by_query API if supported
    # or the application-level implementation.
    #
    # Warning: These implementations have different parameters and return types.
    # If you want to use one or the other consistently, use ElastomerClient::Client#native_delete_by_query
    # or ElastomerClient::Client#app_delete_by_query directly.
    def delete_by_query(query, params = {})
      send(:native_delete_by_query, query, params)
    end
  end
end

```

# lib/elastomer_client/client/docs.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Provides access to document-level API commands. Indexing documents and
    # searching documents are both handled by this module.
    #
    # name - The name of the index as a String (optional)
    # type - The document type as a String (optional)
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html
    #
    # Returns a Docs instance.
    def docs(name = nil, type = nil)
      Docs.new self, name, type
    end

    class Docs
      # Create a new document client for making API requests that pertain to
      # the indexing and searching of documents in a search index.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # name   - The name of the index as a String
      # type   - The document type as a String
      #
      def initialize(client, name, type = nil)
        @client = client
        @name   = @client.assert_param_presence(name, "index name") unless name.nil?
        @type   = @client.assert_param_presence(type, "document type") unless type.nil?
      end

      attr_reader :client, :name, :type

      # Adds or updates a document in the index, making it searchable. If the
      # document contains an `:_id` attribute then PUT semantics will be used to
      # create (or update) a document with that ID. If no ID is provided then a
      # new document will be created using POST semantics.
      #
      # There are several other document attributes that control how
      # Elasticsearch will index the document. They are listed below. Please
      # refer to the Elasticsearch documentation for a full explanation of each
      # and how it affects the indexing process. These indexing directives vary
      # by Elasticsearch version. Attempting to use a directive not supported
      # by the Elasticsearch server will raise an exception.
      #
      #   :_id
      #   :_type
      #   :_version
      #   :_version_type
      #   :_op_type
      #   :_routing
      #   :_parent
      #   :_refresh
      #
      # Elasticsearch 2.X only:
      #
      #   :_consistency
      #
      # Elasticsearch 5.x only:
      #
      #   :_wait_for_active_shards
      #
      # If any of these attributes are present in the document they will be
      # removed from the document before it is indexed. This means that the
      # document will be modified by this method.
      #
      # document - The document (as a Hash or JSON encoded String) to add to the index
      # params   - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
      #
      # Returns the response body as a Hash
      #
      # Raises ElastomerClient::Client::IllegalArgument if an unsupported indexing
      # directive is used.
      def index(document, params = {})
        overrides = from_document document
        params = update_params(params, overrides)
        params.merge!(action: "docs.index", rest_api: "index")

        params.delete(:id) if params[:id].nil? || params[:id].to_s =~ /\A\s*\z/

        response =
            if params[:id]
              client.put "/{index}/{type}/{id}", params
            else
              client.post "/{index}/{type}", params
            end

        response.body
      end

      # Delete a document from the index based on the document ID. The :id is
      # provided as part of the params hash.
      #
      # params - Parameters Hash
      #   :id - the ID of the document to delete
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete.html
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete "/{index}/{type}/{id}", update_params(params, action: "docs.delete", rest_api: "delete")
        response.body
      end

      # Retrieve a document from the index based on its ID. The :id is
      # provided as part of the params hash.
      #
      # params - Parameters Hash
      #   :id - the ID of the document to get
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html#docs-get
      #
      # Returns the response body as a Hash
      def get(params = {})
        response = client.get "/{index}/{type}/{id}", update_params(params, action: "docs.get", rest_api: "get")
        response.body
      end

      # Check to see if a document exists. The :id is provided as part of the
      # params hash.
      #
      # params - Parameters Hash
      #   :id - the ID of the document to check
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html#docs-get
      #
      # Returns true if the document exists
      def exists?(params = {})
        response = client.head "/{index}/{type}/{id}", update_params(params, action: "docs.exists", rest_api: "exists")
        response.success?
      end
      alias_method :exist?, :exists?

      # Retrieve the document source from the index based on the ID and type.
      # The :id is provided as part of the params hash.
      #
      # params - Parameters Hash
      #   :id - the ID of the document
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html#_source
      #
      # Returns the response body as a Hash
      def source(params = {})
        response = client.get "/{index}/{type}/{id}/_source", update_params(params, action: "docs.source", rest_api: "get_source")
        response.body
      end

      # Allows you to get multiple documents based on an index, type, and id (and possibly routing).
      #
      # body   - The request body as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-get.html
      #
      # Returns the response body as a Hash
      def multi_get(body, params = {})
        overrides = from_document body
        overrides.merge!(action: "docs.multi_get", rest_api: "mget")

        response = client.get "{/index}{/type}/_mget", update_params(params, overrides, client.version_support.es_version_8_plus?)
        response.body
      end
      alias_method :mget, :multi_get

      # Update a document based on a script provided.
      #
      # script - The script (as a Hash) used to update the document in place
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update.html
      #
      # Returns the response body as a Hash
      def update(script, params = {})
        overrides = from_document script
        overrides.merge!(action: "docs.update", rest_api: "update")

        if client.version_support.es_version_8_plus?
          response = client.post "/{index}/_update/{id}", update_params(params, overrides, true)
        else
          response = client.post "/{index}/{type}/{id}/_update", update_params(params, overrides)
        end
        response.body
      end

      # Allows you to execute a search query and get back search hits that
      # match the query. This method supports both the "request body" query
      # and the "URI request" query. When using the request body semantics,
      # the query hash must contain the :query key. Otherwise we assume a URI
      # request is being made.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #
      # Examples
      #
      #   # request body query
      #   search({query: {match_all: {}}}, type: 'tweet')
      #
      #   # same thing but using the URI request method
      #   search(q: '*:*', type: 'tweet')
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-uri-request.html
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-body.html
      #
      # Returns the response body as a hash
      def search(query, params = nil)
        query, params = extract_params(query) if params.nil?

        response = client.get "/{index}{/type}/_search", update_params(params, {body: query, action: "docs.search", rest_api: "search"}, client.version_support.es_version_8_plus?)
        response.body
      end

      # The search shards API returns the indices and shards that a search
      # request would be executed against. This can give useful feedback for
      # working out issues or planning optimizations with routing and shard
      # preferences.
      #
      # params - Parameters Hash
      #   :routing    - routing values
      #   :preference - which shard replicas to execute the search request on
      #   :local      - boolean value to use local cluster state
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-shards.html
      #
      # Returns the response body as a hash
      def search_shards(params = {})
        updated_params = update_params(params, { action: "docs.search_shards", rest_api: "search_shards" }, true)

        response = client.get "/{index}/_search_shards", updated_params
        response.body
      end

      # Executes a search query, but instead of returning results, returns
      # the number of documents matched. This method supports both the
      # "request body" query and the "URI request" query. When using the
      # request body semantics, the query hash must contain the :query key.
      # Otherwise we assume a URI request is being made.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #
      # Examples
      #
      #   # request body query
      #   count({match_all: {}}, type: 'tweet')
      #
      #   # same thing but using the URI request method
      #   count(q: '*:*', type: 'tweet')
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-count.html
      #
      # Returns the response body as a Hash
      def count(query, params = nil)
        query, params = extract_params(query) if params.nil?

        if client.version_support.es_version_8_plus?
          response = client.get "/{index}/_count", update_params(params, {body: query, action: "docs.count", rest_api: "count"}, true)
        else
          response = client.get "/{index}{/type}/_count", update_params(params, body: query, action: "docs.count", rest_api: "count")
        end
        response.body
      end

      # Delete documents by query
      def delete_by_query(query, params = nil)
        send(:native_delete_by_query, query, params)
      end

      # Delete documents from one or more indices and one or more types based
      # on a query using Elasticsearch's _delete_by_query API.
      #
      # See Client#native_delete_by_query for more information.
      #
      # Returns a Hash of statistics about the delete operations as returned by
      # _delete_by_query.
      #
      # Raises ElastomerClient::Client::IncompatibleVersionException if this version
      # of Elasticsearch does not support _delete_by_query.
      def native_delete_by_query(query, params = {})
        query, params = extract_params(query) if params.nil?

        @client.native_delete_by_query(query, update_params(params))
      end

      # Update documents by query using Elasticsearch's _update_by_query API.
      #
      # See Client#update_by_query for more information.
      #
      # Returns a Hash of statistics about the update operations as returned by
      # _update_by_query.
      def update_by_query(query, params = nil)
        query, params = extract_params(query) if params.nil?

        @client.update_by_query(query, update_params(params))
      end

      # Matches a provided or existing document to the stored percolator
      # queries. To match an existing document, pass `nil` as the body and
      # include `:id` in the params.
      #
      # Examples
      #
      #   index.percolator(1).create query: { match: { author: "pea53" } }
      #   docs.percolate doc: { author: "pea53" }
      #   docs.percolate nil, id: 3
      #
      # Returns the response body as a Hash
      def percolate(body, params = {})
        response = client.get "/{index}/{type}{/id}/_percolate", update_params(params, body:, action: "percolator.percolate", rest_api: "percolate")
        response.body
      end

      # Counts the queries that match a provided or existing document. To count
      # matches for an existing document, pass `nil` as the body and include
      # `:id` in the params.
      #
      # Examples
      #
      #   index.register_percolator_query 1, query: { match: { author: "pea53" } }
      #   docs.percolate_count doc: { author: "pea53" }
      #   docs.percolate_count nil, id: 3
      #
      # Returns the count
      def percolate_count(body, params = {})
        response = client.get "/{index}/{type}{/id}/_percolate/count", update_params(params, body:, action: "percolator.percolate_count", rest_api: "count_percolate")
        response.body["total"]
      end

      # Returns information and statistics on terms in the fields of a
      # particular document as stored in the index. The :id is provided as part
      # of the params hash.
      #
      # params - Parameters Hash
      #   :id - the ID of the document to get
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-termvectors.html
      #
      # Returns the response body as a hash
      def termvector(params = {})
        if client.version_support.es_version_8_plus?
          response = client.get "/{index}/_termvectors/{id}", update_params(params, {action: "docs.termvector", rest_api: "termvectors"}, true)
        else
          response = client.get "/{index}/{type}/{id}/_termvectors", update_params(params, action: "docs.termvector", rest_api: "termvectors")
        end
        response.body
      end
      alias_method :termvectors, :termvector
      alias_method :term_vector, :termvector
      alias_method :term_vectors, :termvector

      # Multi termvectors API allows you to get multiple termvectors based on
      # an index, type and id. The response includes a docs array with all the
      # fetched termvectors, each element having the structure provided by the
      # `termvector` API.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-termvectors.html
      #
      # Returns the response body as a hash
      def multi_termvectors(body, params = {})
        response = client.get "{/index}{/type}/_mtermvectors", update_params(params, {body:, action: "docs.multi_termvectors", rest_api: "mtermvectors"}, client.version_support.es_version_8_plus?)
        response.body
      end
      alias_method :multi_term_vectors, :multi_termvectors

# Percolate

      # Compute a score explanation for a query and a specific document. This
      # can give useful feedback about why a document matched or didn't match
      # a query. The document :id is provided as part of the params hash.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #   :id - the ID of the document
      #
      # Examples
      #
      #   explain({query: {term: {"message" => "search"}}}, id: 1)
      #
      #   explain(q: "message:search", id: 1)
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-explain.html
      #
      # Returns the response body as a hash
      def explain(query, params = nil)
        query, params = extract_params(query) if params.nil?

        if client.version_support.es_version_8_plus?
          response = client.get "/{index}/_explain/{id}", update_params(params, {body: query, action: "docs.explain", rest_api: "explain"}, true)
        else
          response = client.get "/{index}/{type}/{id}/_explain", update_params(params, body: query, action: "docs.explain", rest_api: "explain")
        end
        response.body
      end

      # Validate a potentially expensive query before running it. The
      # :explain parameter can be used to get detailed information about
      # why a query failed.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #
      # Examples
      #
      #   # request body query
      #   validate({query: {query_string: {query: "*:*"}}}, explain: true)
      #
      #   # same thing but using the URI query parameter
      #   validate(q: "post_date:foo", explain: true)
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-validate.html
      #
      # Returns the response body as a hash
      def validate(query, params = nil)
        query, params = extract_params(query) if params.nil?

        response = client.get "/{index}{/type}/_validate/query", update_params(params, {body: query, action: "docs.validate", rest_api: "indices.validate_query"}, client.version_support.es_version_8_plus?)
        response.body
      end

      # Perform bulk indexing and/or delete operations. The current index name
      # and document type will be passed to the bulk API call as part of the
      # request parameters.
      #
      # params - Parameters Hash that will be passed to the bulk API call.
      # block  - Required block that is used to accumulate bulk API operations.
      #          All the operations will be passed to the search cluster via a
      #          single API request.
      #
      # Yields a Bulk instance for building bulk API call bodies.
      #
      # Examples
      #
      #   docs.bulk do |b|
      #     b.index( document1 )
      #     b.index( document2 )
      #     b.delete( document3 )
      #     ...
      #   end
      #
      # Returns the response body as a Hash
      def bulk(params = {}, &block)
        raise "a block is required" if block.nil?

        params = {index: self.name, type: self.type}.merge params
        client.bulk params, &block
      end

      # Create a new Scroller instance for scrolling all results from a `query`.
      # The Scroller will be scoped to the current index and document type.
      #
      # query  - The query to scroll as a Hash or a JSON encoded String
      # opts   - Options Hash
      #   :index  - the name of the index to search
      #   :type   - the document type to search
      #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
      #   :size   - the number of documents per shard to fetch per scroll
      #
      # Examples
      #
      #   scroll = index.scroll('{"query":{"match_all":{}},"sort":{"date":"desc"}}')
      #   scroll.each_document do |document|
      #     document['_id']
      #     document['_source']
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
      #
      # Returns a new Scroller instance
      def scroll(query, opts = {})
        opts = {index: name, type:}.merge opts
        client.scroll query, opts
      end

      # Create a new Scroller instance for scanning all results from a `query`.
      # The Scroller will be scoped to the current index and document type. The
      # Scroller is configured to use `scan` semantics which are more efficient
      # than a standard scroll query; the caveat is that the returned documents
      # cannot be sorted.
      #
      # query  - The query to scan as a Hash or a JSON encoded String
      # opts   - Options Hash
      #   :index  - the name of the index to search
      #   :type   - the document type to search
      #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
      #   :size   - the number of documents per shard to fetch per scroll
      #
      # Examples
      #
      #   scan = docs.scan('{"query":{"match_all":{}}}')
      #   scan.each_document do |document|
      #     document['_id']
      #     document['_source']
      #   end
      #
      # Returns a new Scroller instance
      def scan(query, opts = {})
        opts = {index: name, type:}.merge opts
        client.scan query, opts
      end

      # Execute an array of searches in bulk. Results are returned in an
      # array in the order the queries were sent. The current index name
      # and document type will be passed to the multi_search API call as
      # part of the request parameters.
      #
      # params - Parameters Hash that will be passed to the API call.
      # block  - Required block that is used to accumulate searches.
      #          All the operations will be passed to the search cluster
      #          via a single API request.
      #
      # Yields a MultiSearch instance for building multi_search API call
      # bodies.
      #
      # Examples
      #
      #   docs.multi_search do |m|
      #     m.search({query: {match_all: {}}, size: 0)
      #     m.search({query: {field: {"foo" => "bar"}}})
      #     ...
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
      #
      # Returns the response body as a Hash
      def multi_search(params = {}, &block)
        raise "a block is required" if block.nil?

        params = {index: self.name, type: self.type}.merge params
        params.delete(:type) if client.version_support.es_version_8_plus?
        client.multi_search params, &block
      end

      # Execute an array of percolate actions in bulk. Results are returned in
      # an array in the order the actions were sent. The current index name and
      # type will be passed to the API call as part of the request parameters.
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html#_multi_percolate_api
      #
      # params - Optional request parameters as a Hash
      # block  - Passed to a MultiPercolate instance which assembles the
      #          percolate actions into a single request.
      #
      # Examples
      #
      #   # block form
      #   multi_percolate do |m|
      #     m.percolate(author: "pea53")
      #     m.count(author: "grantr")
      #     ...
      #   end
      #
      # Returns the response body as a Hash
      def multi_percolate(params = {}, &block)
        params = defaults.merge params
        client.multi_percolate(params, &block)
      end

      SPECIAL_KEYS= %i[
        index type id version version_type op_type routing parent
        consistency replication refresh wait_for_active_shards
      ].inject({}) { |h, k| h[k] = "_#{k}"; h }.freeze

      # Internal: Given a `document` generate an options hash that will
      # override parameters based on the content of the document. The document
      # will be returned as the value of the :body key.
      #
      # We only extract information from the document if it is given as a
      # Hash. We do not parse JSON encoded Strings.
      #
      # document - A document Hash or JSON encoded String.
      #
      # Returns an options Hash extracted from the document.
      #
      # Raises ElastomerClient::Client::IllegalArgument if an unsupported indexing
      # directive is used.
      def from_document(document)
        opts = {body: document}

        if document.is_a? Hash
          SPECIAL_KEYS.each do |key, field|
            opts[key] = document.delete field if document.key? field
            opts[key] = document.delete field.to_sym if document.key? field.to_sym
          end
        end

        opts
      end

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil, delete_type = false)
        h = defaults.update params
        h.update overrides unless overrides.nil?
        h[:routing] = h[:routing].join(",") if h[:routing].is_a?(Array)
        h[:type] = "_doc" if client.version_support.es_version_8_plus? && !delete_type
        h.delete(:type) if delete_type
        h
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        { index: name, type: }
      end

      # Internal: Allow params to be passed as the first argument to
      # methods that take both an optional query hash and params.
      #
      # query  - query hash OR params hash
      # params - params hash OR nil if no query
      #
      # Returns an array of the query (possibly nil) and params Hash.
      def extract_params(query, params = nil)
        if params.nil?
          if query.key? :query
            params = {}
          else
            params, query = query, nil
          end
        end
        [query, params]
      end

    end
  end
end

```

# lib/elastomer_client/client/errors.rb

```rb
# frozen_string_literal: true

module ElastomerClient

  # Parent class for all ElastomerClient errors.
  Error = Class.new StandardError

  class Client

    # General error response from client requests.
    class Error < ::ElastomerClient::Error

      # Construct a new Error from the given response object or a message
      # String. If a response object is given, the error message will be
      # extracted from the response body.
      #
      # response - Faraday::Response object or a simple error message String
      #
      def initialize(*args)
        @status = nil
        @error = nil

        case args.first
        when Exception
          exception = args.shift
          super("#{exception.message} :: #{args.join(' ')}")
          set_backtrace exception.backtrace

        when Faraday::Response
          response = args.shift
          @status = response.status

          body = response.body
          @error = body["error"] if body.is_a?(Hash) && body.key?("error")

          message = @error || body.to_s
          super(message)

        else
          super(args.join(" "))
        end
      end

      # Returns the status code from the `response` or nil if the Error was not
      # created with a response.
      attr_reader :status

      # Returns the Elasticsearch error from the `response` or nil if the Error
      # was not created with a response.
      attr_reader :error

      # Indicates that the error is fatal. The request should not be tried
      # again.
      def fatal?
        self.class.fatal?
      end

      # The inverse of the `fatal?` method. A request can be retried if this
      # method returns `true`.
      def retry?
        !fatal?
      end

      class << self
        # By default all client errors are fatal and indicate that a request
        # should not be retried. Only a few errors are retryable.
        def fatal
          return @fatal if defined? @fatal
          @fatal = true
        end
        attr_writer :fatal
        alias_method :fatal?, :fatal
      end

    end  # Error

    # Wrapper classes for specific Faraday errors.
    TimeoutError     = Class.new Error
    ConnectionFailed = Class.new Error
    ResourceNotFound = Class.new Error
    ParsingError     = Class.new Error
    SSLError         = Class.new Error
    ServerError      = Class.new Error
    RequestError     = Class.new Error
    RequestSizeError = Class.new Error

    # Provide some nice errors for common Elasticsearch exceptions. These are
    # all subclasses of the more general RequestError
    IndexNotFoundError = Class.new RequestError
    QueryParsingError = Class.new RequestError
    SearchContextMissing = Class.new RequestError
    RejectedExecutionError = Class.new RequestError
    DocumentAlreadyExistsError = Class.new RequestError

    ServerError.fatal            = false
    TimeoutError.fatal           = false
    ConnectionFailed.fatal       = false
    RejectedExecutionError.fatal = false

    # Exception for operations that are unsupported with the version of
    # Elasticsearch being used.
    IncompatibleVersionException = Class.new Error

    # Exception for client-detected and server-raised invalid Elasticsearch
    # request parameter.
    IllegalArgument = Class.new Error

  end
end

```

# lib/elastomer_client/client/index.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Provides access to index-level API commands. An index name is required for
    # these API calls. If you want to operate on all indices - flushing all
    # indices, for example - then you will need to use the "_all" index name.
    #
    # You can override the index name for one-off calls by passing in the
    # desired index name via the `:index` option.
    #
    # name - The name of the index as a String or an Array of names
    #
    # Returns an Index instance.
    def index(name = nil)
      Index.new self, name
    end

    class Index
      # Create a new index client for making API requests that pertain to
      # the health and management of individual indexes.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # name   - The name of the index as a String or an Array of names
      #
      def initialize(client, name)
        @client = client
        @name   = @client.assert_param_presence(name, "index name") unless name.nil?
      end

      attr_reader :client, :name

      # Check for the existence of the index. If a `:type` option is given, then
      # we will check for the existence of the document type in the index.
      #
      # params - Parameters Hash
      #   :type - optional type mapping as a String
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-exists.html
      # and https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-types-exists.html
      #
      # Returns true if the index (or type) exists
      def exists?(params = {})
        response = client.head "/{index}{/type}", update_params(params, action: "index.exists", rest_api: "indices.exists")
        response.success?
      end
      alias_method :exist?, :exists?

      # Create the index.
      #
      # body   - The index settings and mappings as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-create-index.html
      #
      # Returns the response body as a Hash
      def create(body, params = {})
        response = client.put "/{index}", update_params(params, body:, action: "index.create", rest_api: "indices.create")
        response.body
      end

      # Delete the index.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-delete-index.html
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete "/{index}", update_params(params, action: "index.delete", rest_api: "indices.delete")
        response.body
      end

      # Open the index.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-open-close.html
      #
      # Returns the response body as a Hash
      def open(params = {})
        response = client.post "/{index}/_open", update_params(params, action: "index.open", rest_api: "indices.open")
        response.body
      end

      # Close the index.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-open-close.html
      #
      # Returns the response body as a Hash
      def close(params = {})
        response = client.post "/{index}/_close", update_params(params, action: "index.close", rest_api: "indices.close")
        response.body
      end

      # Retrieve the settings for the index.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-get-settings.html
      #
      # Returns the response body as a Hash
      def get_settings(params = {})
        response = client.get "{/index}/_settings", update_params(params, action: "index.get_settings", rest_api: "indices.get_settings")
        response.body
      end
      alias_method :settings, :get_settings

      # Change specific index level settings in real time.
      #
      # body   - The index settings as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-update-settings.html
      #
      # Returns the response body as a Hash
      def update_settings(body, params = {})
        response = client.put "{/index}/_settings", update_params(params, body:, action: "index.update_settings", rest_api: "indices.put_settings")
        response.body
      end

      # Retrieve one or more mappings from the index. To retrieve a specific
      # mapping provide the name as the `:type` parameter.
      #
      # params - Parameters Hash
      #   :type - specific document type as a String or Array of Strings
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-get-mapping.html
      #
      # Returns the response body as a Hash
      def get_mapping(params = {})
        response = client.get "/{index}/_mapping{/type}", update_params(params, action: "index.get_mapping", rest_api: "indices.get_mapping")
        response.body
      end
      alias_method :mapping, :get_mapping

      # Register specific mapping definition for a specific type.
      #
      # type   - Name of the mapping to update as a String
      # body   - The mapping values to update as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-put-mapping.html
      #
      # Returns the response body as a Hash
      def update_mapping(type, body, params = {})
        response = client.put "/{index}/_mapping{/type}", update_params(params, body:, type:, action: "index.update_mapping", rest_api: "indices.put_mapping")
        response.body
      end
      alias_method :put_mapping, :update_mapping

      # Return the aliases associated with this index.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def get_aliases(params = {})
        response = client.get "/{index}/_alias", update_params(action: "index.get_aliases", rest_api: "indices.get_alias")
        response.body
      end
      alias_method :aliases, :get_aliases

      # Return the named aliases associated with this index.
      #
      # name   - Name of the alias to look up
      # params - Parameters Hash
      #   :ignore_unavailable - What to do if a specified index name doesn’t
      #                         exist. If set to `true` then those indices are ignored.
      #
      # Examples
      #
      #   index.get_alias("*")       # returns all aliases for the current index
      #   index.get_alias("issue*")  # returns all aliases starting with "issue"
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def get_alias(name, params = {})
        response = client.get "/{index}/_alias/{name}", update_params(params, name:, action: "index.get_alias", rest_api: "indices.get_alias")
        response.body
      end

      # Add a single alias to this index.
      #
      # name   - Name of the alias to add to the index
      # params - Parameters Hash
      #   :routing - optional routing that can be associated with an alias
      #   :filter  - optional filter that can be associated with an alias
      #
      # Examples
      #
      #   index.add_alias("foo", routing: "foo")
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def add_alias(name, params = {})
        response = client.put "/{index}/_alias/{name}", update_params(params, name:, action: "index.add_alias", rest_api: "indices.put_alias")
        response.body
      end

      # Delete an alias from this index.
      #
      # name   - Name of the alias to delete from the index
      # params - Parameters Hash
      #
      # Examples
      #
      #   index.delete_alias("foo")
      #   index.delete_alias(["foo", "bar"])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
      #
      # Returns the response body as a Hash
      def delete_alias(name, params = {})
        response = client.delete "/{index}/_alias/{name}", update_params(params, name:, action: "index.delete_alias", rest_api: "indices.delete_alias")
        response.body
      end

      # Perform the analysis process on some text and return the tokens
      # breakdown of the text.
      #
      # text   - The text to analyze as a String
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-analyze.html
      #
      # Returns the response body as a Hash
      def analyze(text, params = {})
        body = text.is_a?(Hash) ? text : {text: text.to_s}
        response = client.get "{/index}/_analyze", update_params(params, body:, action: "index.analyze", rest_api: "indices.analyze")
        response.body
      end

      # Explicitly refresh one or more index, making all operations performed
      # since the last refresh available for search.
      #
      # params - Parameters Hash
      #   :index - set to "_all" to refresh all indices
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-refresh.html
      #
      # Returns the response body as a Hash
      def refresh(params = {})
        response = client.post "{/index}/_refresh", update_params(params, action: "index.refresh", rest_api: "indices.refresh")
        response.body
      end

      # Flush one or more indices to the index storage.
      #
      # params - Parameters Hash
      #   :index - set to "_all" to flush all indices
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-flush.html
      #
      # Returns the response body as a Hash
      def flush(params = {})
        response = client.post "{/index}/_flush", update_params(params, action: "index.flush", rest_api: "indices.flush")
        response.body
      end

      # Force merge one or more indices. Force merging an index allows to
      # reduce the number of segments but can be resource intensive.
      #
      # params - Parameters Hash
      #   :index - set to "_all" to force merge all indices
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-forcemerge.html
      #
      # Returns the response body as a Hash
      def forcemerge(params = {})
        response = client.post "{/index}/_forcemerge", update_params(params, action: "index.forcemerge", rest_api: "indices.forcemerge")
        response.body
      end
      # DEPRECATED:  ES 5.X has removed the `/_optimize` endpoint.
      alias_method :optimize, :forcemerge

      # Provides insight into ongoing index shard recoveries. Recovery status
      # may be reported for specific indices, or cluster-wide.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-recovery.html
      #
      # Returns the response body as a Hash
      def recovery(params = {})
        response = client.get "{/index}/_recovery", update_params(params, action: "index.recovery", rest_api: "indices.recovery")
        response.body
      end

      # Clear caches for one or more indices. Individual caches can be
      # specified with parameters.
      #
      # params - Parameters Hash
      #   :index - set to "_all" to clear all index caches
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-clearcache.html
      #
      # Returns the response body as a Hash
      def clear_cache(params = {})
        response = client.post "{/index}/_cache/clear", update_params(params, action: "index.clear_cache", rest_api: "indices.clear_cache")
        response.body
      end

      # Retrieve statistics about one or more indices. Specific statistics
      # can be retrieved with parameters.
      #
      # params - Parameters Hash
      #   :stats - a single stats value or an Array of stats values
      #
      # Examples
      #
      #   stats(stats: "docs")
      #   stats(stats: %w[flush merge])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-stats.html
      #
      # Returns the response body as a Hash
      def stats(params = {})
        response = client.get "{/index}/_stats{/stats}", update_params(params, action: "index.stats", rest_api: "indices.stats")
        response.body
      end

      # Retrieve low level Lucene segments information for shards of one
      # or more indices.
      #
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-segments.html
      #
      # Returns the response body as a Hash
      def segments(params = {})
        response = client.get "{/index}/_segments", update_params(params, action: "index.segments", rest_api: "indices.segments")
        response.body
      end

      # Provides access to document-level API commands. These commands will be
      # scoped to this index and the give `type`, if any.
      #
      # type - The document type as a String
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html
      #
      # Returns a Docs instance.
      def docs(type = nil)
        type = "_doc" if client.version_support.es_version_8_plus?
        client.docs name, type
      end

      # Exposes the `/_suggest` endpoint of the Elasticsearch API.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-suggesters.html
      #
      # Returns the response body as a Hash
      def suggest(query, params = {})
        response = client.post "{/index}/_suggest", update_params(params, body: query, action: "index.suggest", rest_api: "suggest")
        response.body
      end

      # Perform bulk indexing and/or delete operations. The current index name
      # will be passed to the bulk API call as part of the request parameters.
      #
      # params - Parameters Hash that will be passed to the bulk API call.
      # block  - Required block that is used to accumulate bulk API operations.
      #          All the operations will be passed to the search cluster via a
      #          single API request.
      #
      # Yields a Bulk instance for building bulk API call bodies.
      #
      # Examples
      #
      #   index.bulk do |b|
      #     b.index( document1 )
      #     b.index( document2 )
      #     b.delete( document3 )
      #     ...
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
      #
      # Returns the response body as a Hash
      def bulk(params = {}, &block)
        raise "a block is required" if block.nil?

        params = {index: self.name}.merge params
        client.bulk params, &block
      end

      # Create a new Scroller instance for scrolling all results from a `query`.
      # The Scroller will be scoped to the current index.
      #
      # query  - The query to scroll as a Hash or a JSON encoded String
      # opts   - Options Hash
      #   :index  - the name of the index to search
      #   :type   - the document type to search
      #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
      #   :size   - the number of documents per shard to fetch per scroll
      #
      # Examples
      #
      #   scroll = index.scroll('{"query":{"match_all":{}},"sort":{"date":"desc"}}')
      #   scroll.each_document do |document|
      #     document['_id']
      #     document['_source']
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
      #
      # Returns a new Scroller instance
      def scroll(query, opts = {})
        opts = {index: name}.merge opts
        client.scroll query, opts
      end

      # Create a new Scroller instance for scanning all results from a `query`.
      # The Scroller will be scoped to the current index. The Scroller is
      # configured to use `scan` semantics which are more efficient than a
      # standard scroll query; the caveat is that the returned documents cannot
      # be sorted.
      #
      # query  - The query to scan as a Hash or a JSON encoded String
      # opts   - Options Hash
      #   :index  - the name of the index to search
      #   :type   - the document type to search
      #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
      #   :size   - the number of documents per shard to fetch per scroll
      #
      # Examples
      #
      #   scan = index.scan('{"query":{"match_all":{}}}')
      #   scan.each_document do |document|
      #     document['_id']
      #     document['_source']
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
      #
      # Returns a new Scroller instance
      def scan(query, opts = {})
        opts = {index: name}.merge opts
        client.scan query, opts
      end

      # Execute an array of searches in bulk. Results are returned in an
      # array in the order the queries were sent. The current index name
      # will be passed to the multi_search API call as part of the request
      # parameters.
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
      #
      # params - Parameters Hash that will be passed to the API call.
      # block  - Required block that is used to accumulate searches.
      #          All the operations will be passed to the search cluster
      #          via a single API request.
      #
      # Yields a MultiSearch instance for building multi_search API call
      # bodies.
      #
      # Examples
      #
      #   index.multi_search do |m|
      #     m.search({query: {match_all: {}}, size: 0)
      #     m.search({query: {field: {"author" => "grantr"}}}, type: 'tweet')
      #     ...
      #   end
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
      #
      # Returns the response body as a Hash
      def multi_search(params = {}, &block)
        raise "a block is required" if block.nil?

        params = {index: self.name}.merge params
        client.multi_search params, &block
      end

      # Execute an array of percolate actions in bulk. Results are returned in
      # an array in the order the actions were sent. The current index name will
      # be passed to the API call as part of the request parameters.
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html#_multi_percolate_api
      #
      # params - Optional request parameters as a Hash
      # block  - Passed to a MultiPercolate instance which assembles the
      #          percolate actions into a single request.
      #
      # Examples
      #
      #   # block form
      #   multi_percolate do |m|
      #     m.percolate({ author: "pea53" }, { type: 'default-type' })
      #     m.count({ author: "pea53" }, { type: 'type2' })
      #     ...
      #   end
      #
      # Returns the response body as a Hash
      def multi_percolate(params = {}, &block)
        params = defaults.merge params
        client.multi_percolate(params, &block)
      end

      # Delete documents by query
      def delete_by_query(query, params = nil)
        docs.send(:native_delete_by_query, query, params)
      end

      # Delete documents from one or more indices and one or more types based
      # on a query using Elasticsearch's _delete_by_query API.
      #
      # See Client#native_delete_by_query for more information.
      #
      # Returns a Hash of statistics about the delete operations as returned by
      # _delete_by_query.
      #
      # Raises ElastomerClient::Client::IncompatibleVersionException if this version
      # of Elasticsearch does not support _delete_by_query.
      def native_delete_by_query(query, params = nil)
        docs.native_delete_by_query(query, params)
      end

      # Update documents by query using Elasticsearch's _update_by_query API.
      #
      # See Client#update_by_query for more information.
      #
      # Returns a Hash of statistics about the update operations as returned by
      # _update_by_query.
      def update_by_query(query, params = nil)
        docs.update_by_query(query, params)
      end

      # Constructs a Percolator with the given id on this index.
      #
      # Examples
      #
      #   index.percolator "1"
      #
      # Returns a Percolator
      def percolator(id)
        Percolator.new(client, name, id)
      end

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil)
        h = defaults.update params
        h.update overrides unless overrides.nil?
        h.delete(:type) if client.version_support.es_version_8_plus?
        h
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        { index: name }
      end

    end
  end
end

```

# lib/elastomer_client/client/multi_percolate.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Execute an array of percolate actions in bulk. Results are returned in an
    # array in the order the actions were sent.
    #
    # The `multi_percolate` method can be used in two ways. Without a block
    # the method will perform an API call, and it requires a bulk request
    # body and optional request parameters.
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-percolate.html#_multi_percolate_api
    #
    # body   - Request body as a String (required if a block is not given)
    # params - Optional request parameters as a Hash
    # block  - Passed to a MultiPercolate instance which assembles the
    #          percolate actions into a single request.
    #
    # Examples
    #
    #   # index and type in request body
    #   multi_percolate(request_body)
    #
    #   # index in URI
    #   multi_percolate(request_body, index: 'default-index')
    #
    #   # block form
    #   multi_percolate(index: 'default-index') do |m|
    #     m.percolate({ author: "pea53" }, { type: 'default-type' })
    #     m.count({ author: "pea53" }, { type: 'type2' })
    #     ...
    #   end
    #
    # Returns the response body as a Hash
    def multi_percolate(body = nil, params = nil)
      if block_given?
        params, body = (body || {}), nil
        yield mpercolate_obj = MultiPercolate.new(self, params)
        mpercolate_obj.call
      else
        raise "multi_percolate request body cannot be nil" if body.nil?
        params ||= {}

        response = self.post "{/index}{/type}/_mpercolate", params.merge(body:, action: "mpercolate", rest_api: "mpercolate")
        response.body
      end
    end
    alias_method :mpercolate, :multi_percolate

    # The MultiPercolate class is a helper for accumulating and submitting
    # multi_percolate API requests. Instances of the MultiPercolate class
    # accumulate percolate actions and then issue a single API request to
    # Elasticsearch, which runs all accumulated percolate actions in parallel
    # and returns each result hash aggregated into an array of result
    # hashes.
    #
    # Instead of instantiating this class directly, use
    # the block form of Client#multi_percolate.
    #
    class MultiPercolate

      # Create a new MultiPercolate instance for accumulating percolate actions
      # and submitting them all as a single request.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # params - Parameters Hash to pass to the Client#multi_percolate method
      def initialize(client, params = {})
        @client  = client
        @params  = params

        @actions = []
      end

      attr_reader :client

      # Add a percolate action to the multi percolate request. This percolate
      # action will not be executed until the multi_percolate API call is made.
      #
      # header - A Hash of the index and type, if not provided in the params
      # doc    - A Hash of the document
      #
      # Returns this MultiPercolate instance.
      def percolate(doc, header = {})
        add_to_actions(percolate: @params.merge(header))
        add_to_actions(doc:)
      end

      # Add a percolate acount action to the multi percolate request. This
      # percolate count action will not be executed until the multi_percolate
      # API call is made.
      #
      # header - A Hash of the index and type, if not provided in the params
      # doc    - A Hash of the document
      #
      # Returns this MultiPercolate instance.
      def count(doc, header = {})
        add_to_actions(count: @params.merge(header))
        add_to_actions(doc:)
      end

      # Execute the multi_percolate call with the accumulated percolate actions.
      # If the accumulated actions list is empty then no action is taken.
      #
      # Returns the response body Hash.
      def call
        return if @actions.empty?

        body = @actions.join("\n") + "\n"
        client.multi_percolate(body, @params)
      ensure
        @actions.clear
      end

      # Internal: Add an action to the pending request. Actions can be
      # either headers or bodies. The first action must be a percolate header,
      # followed by a body, then alternating headers and bodies.
      #
      # action - the Hash (header or body) to add to the pending request
      #
      # Returns this MultiPercolate instance.
      def add_to_actions(action)
        action = MultiJson.dump action
        @actions << action
        self
      end
    end
  end
end

```

# lib/elastomer_client/client/multi_search.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Execute an array of searches in bulk. Results are returned in an
    # array in the order the queries were sent.
    #
    # The `multi_search` method can be used in two ways. Without a block
    # the method will perform an API call, and it requires a bulk request
    # body and optional request parameters.
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
    #
    # body   - Request body as a String (required if a block is not given)
    # params - Optional request parameters as a Hash
    # block  - Passed to a MultiSearch instance which assembles the searches
    #          into a single request.
    #
    # Examples
    #
    #   # index and type in request body
    #   multi_search(request_body)
    #
    #   # index in URI
    #   multi_search(request_body, index: 'default-index')
    #
    #   # block form
    #   multi_search(index: 'default-index') do |m|
    #     m.search({query: {match_all: {}}, size: 0)
    #     m.search({query: {field: {"foo" => "bar"}}}, type: 'default-type')
    #     ...
    #   end
    #
    # Returns the response body as a Hash
    def multi_search(body = nil, params = nil)
      if block_given?
        params, body = (body || {}), nil
        yield msearch_obj = MultiSearch.new(self, params)
        msearch_obj.call
      else
        raise "multi_search request body cannot be nil" if body.nil?
        params ||= {}

        response = self.post "{/index}{/type}/_msearch", params.merge(body:, action: "msearch", rest_api: "msearch")
        response.body
      end
    end
    alias_method :msearch, :multi_search

    # The MultiSearch class is a helper for accumulating and submitting
    # multi_search API requests. Instances of the MultiSearch class
    # accumulate searches and then issue a single API request to
    # Elasticsearch, which runs all accumulated searches in parallel
    # and returns each result hash aggregated into an array of result
    # hashes.
    #
    # Instead of instantiating this class directly, use
    # the block form of Client#multi_search.
    #
    class MultiSearch

      # Create a new MultiSearch instance for accumulating searches and
      # submitting them all as a single request.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # params - Parameters Hash to pass to the Client#multi_search method
      def initialize(client, params = {})
        @client  = client
        @params  = params

        @actions = []
      end

      attr_reader :client

      # Add a search to the multi search request. This search will not
      # be executed until the multi_search API call is made.
      #
      # query  - The query body as a Hash
      # params - Parameters Hash
      #
      # Returns this MultiSearch instance.
      def search(query, params = {})
        add_to_actions(params)
        add_to_actions(query)
      end

      # Execute the multi_search call with the accumulated searches. If
      # the accumulated actions list is empty then no action is taken.
      #
      # Returns the response body Hash.
      def call
        return if @actions.empty?

        body = @actions.join("\n") + "\n"
        client.multi_search(body, @params)
      ensure
        @actions.clear
      end

      # Internal: Add an action to the pending request. Actions can be
      # either search params or query bodies. The first action must be
      # a search params hash, followed by a query body, then alternating
      # params and queries.
      #
      # action - the Hash (params or query) to add to the pending request
      #
      # Returns this MultiSearch instance.
      def add_to_actions(action)
        action = MultiJson.dump action
        @actions << action
        self
      end
    end
  end
end

```

# lib/elastomer_client/client/native_delete_by_query.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client
    # Delete documents based on a query using the Elasticsearch _delete_by_query API.
    #
    # query  - The query body as a Hash
    # params - Parameters Hash
    #
    # Examples
    #
    #   # request body query
    #   native_delete_by_query({query: {match_all: {}}}, type: 'tweet')
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/5.6/docs-delete-by-query.html
    #
    # Returns a Hash containing the _delete_by_query response body.
    def native_delete_by_query(query, parameters = {})
      NativeDeleteByQuery.new(self, query, parameters).execute
    end

    class NativeDeleteByQuery
      attr_reader :client, :query, :parameters

      def initialize(client, query, parameters)
        @client = client
        @query = query
        @parameters = parameters
      end

      def execute
        # TODO: Require index parameter. type is optional.
        updated_params = parameters.merge(body: query, action: "delete_by_query", rest_api: "delete_by_query")
        updated_params.delete(:type) if client.version_support.es_version_8_plus?
        response = client.post("/{index}{/type}/_delete_by_query", updated_params)
        response.body
      end
    end
  end
end

```

# lib/elastomer_client/client/nodes.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Provides access to node-level API commands. The default node is set to
    # nil which target all nodes. You can pass in "_all" (to get the
    # same effect) or "_local" to target only the current node the client is
    # connected to. And you can specify an individual node or multiple nodes.
    #
    # node_id - The node ID as a String or an Array of node IDs
    #
    # Returns a Nodes instance.
    def nodes(node_id = nil)
      Nodes.new self, node_id
    end


    class Nodes
      # Create a new nodes client for making API requests that pertain to
      # the health and management individual nodes.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # node_id - The node ID as a String or an Array of node IDs
      #
      def initialize(client, node_id)
        @client  = client
        @node_id = node_id
      end

      attr_reader :client, :node_id

      # Retrieve one or more (or all) of the cluster nodes information. By
      # default all information is returned from all nodes. You can select the
      # information to be returned by passing in the `:info` from the list of
      # "settings", "os", "process", "jvm", "thread_pool", "network",
      # "transport", "http" and "plugins".
      #
      # params - Parameters Hash
      #   :node_id - a single node ID or Array of node IDs
      #   :info    - a single information attribute or an Array
      #
      # Examples
      #
      #   info(info: "_all")
      #   info(info: "os")
      #   info(info: %w[os jvm process])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-info.html
      #
      # Returns the response as a Hash
      def info(params = {})
        response = client.get "/_nodes{/node_id}{/info}", update_params(params, action: "nodes.info", rest_api: "nodes.info")
        response.body
      end

      # Retrieve one or more (or all) of the cluster nodes statistics. For 1.x
      # stats filtering, use the :stats parameter key.
      #
      # params - Parameters Hash
      #   :node_id - a single node ID or Array of node IDs
      #   :stats   - a single stats value or an Array of stats values
      #
      # Examples
      #
      #   stats(stats: "thread_pool")
      #   stats(stats: %w[os process])
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-stats.html
      #
      # Returns the response as a Hash
      def stats(params = {})
        response = client.get "/_nodes{/node_id}/stats{/stats}", update_params(params, action: "nodes.stats", rest_api: "nodes.stats")
        response.body
      end

      # Get the current hot threads on each node in the cluster. The return
      # value is a human formatted String - i.e. a String with newlines and
      # other formatting characters suitable for display in a terminal window.
      #
      # params - Parameters Hash
      #   :node_id  - a single node ID or Array of node IDs
      #   :threads  - number of hot threads to provide
      #   :interval - sampling interval [default is 500ms]
      #   :type     - the type to sample: "cpu", "wait", or "block"
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-hot-threads.html
      #
      # Returns the response as a String
      def hot_threads(params = {})
        response = client.get "/_nodes{/node_id}/hot_threads", update_params(params, action: "nodes.hot_threads", rest_api: "nodes.hot_threads")
        response.body
      end

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil)
        h = { node_id: }.update params
        h.update overrides unless overrides.nil?
        h
      end

    end
  end
end

```

# lib/elastomer_client/client/percolator.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    class Percolator

      # Create a new Percolator for managing a query.
      #
      # client     - ElastomerClient::Client used for HTTP requests to the server
      # index_name - The index name
      # id         - The _id for the query
      def initialize(client, index_name, id)
        @client = client
        @index_name = client.assert_param_presence(index_name, "index name")
        @id = client.assert_param_presence(id, "id")
      end

      attr_reader :client, :index_name, :id

      # Create a percolator query.
      #
      # Examples
      #
      #   percolator = $client.index("default-index").percolator "1"
      #   percolator.create query: { match_all: { } }
      #
      # Returns the response body as a Hash
      def create(body, params = {})
        response = client.put("/{index}/percolator/{id}", defaults.merge(params.merge(body:, action: "percolator.create")))
        response.body
      end

      # Gets a percolator query.
      #
      # Examples
      #
      #   percolator = $client.index("default-index").percolator "1"
      #   percolator.get
      #
      # Returns the response body as a Hash
      def get(params = {})
        response = client.get("/{index}/percolator/{id}", defaults.merge(params.merge(action: "percolator.get")))
        response.body
      end

      # Delete a percolator query.
      #
      # Examples
      #
      #   percolator = $client.index("default-index").percolator "1"
      #   percolator.delete
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete("/{index}/percolator/{id}", defaults.merge(params.merge(action: "percolator.delete")))
        response.body
      end

      # Checks for the existence of a percolator query.
      #
      # Examples
      #
      #   percolator = $client.index("default-index").percolator "1"
      #   percolator.exists?
      #
      # Returns a boolean
      def exists?(params = {})
        get(params)["found"]
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        {index: index_name, id:}
      end

    end  # Percolator
  end  # Client
end  # ElastomerClient

```

# lib/elastomer_client/client/reindex.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Returns a Reindex instance
    def reindex
      Reindex.new(self)
    end

    class Reindex
      # Create a new Reindex for initiating reindex tasks.
      # More context: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html
      #
      # client     - ElastomerClient::Client used for HTTP requests to the server
      def initialize(client)
        @client = client
      end

      attr_reader :client

      def reindex(body, params = {})
        response = client.post "/_reindex", params.merge(params, body:, action: "reindex", rest_api: "reindex")
        response.body
      end

      def rethrottle(task_id, params = {})
        response = client.post "/_reindex/#{task_id}/_rethrottle", params.merge(params, action: "rethrottle", rest_api: "reindex")
        response.body
      end

    end
  end
end

```

# lib/elastomer_client/client/repository.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Returns a Repository instance.
    def repository(name = nil)
      Repository.new(self, name)
    end

    class Repository
      # Create a new index client for making API requests that pertain to
      # the health and management individual indexes.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # name   - The name of the index as a String or an Array of names
      def initialize(client, name = nil)
        @client = client
        @name   = @client.assert_param_presence(name, "repository name") unless name.nil?
      end

      attr_reader :client, :name

      # Check for the existence of the repository.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # params - Parameters Hash
      #
      # Returns true if the repository exists
      def exists?(params = {})
        response = client.get "/_snapshot{/repository}", update_params(params, action: "repository.exists", rest_api: "snapshot.get_repository")
        response.success?
      rescue ElastomerClient::Client::Error => err
        if err.error && err.error.dig("root_cause", 0, "type") == "repository_missing_exception"
          false
        else
          raise err
        end
      end
      alias_method :exist?, :exists?

      # Create the repository.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # body   - The repository type and settings as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def create(body, params = {})
        response = client.put "/_snapshot/{repository}", update_params(params, body:, action: "repository.create", rest_api: "snapshot.create_repository")
        response.body
      end

      # Get repository type and settings.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def get(params = {})
        response = client.get "/_snapshot{/repository}", update_params(params, action: "repository.get", rest_api: "snapshot.get_repository")
        response.body
      end

      # Get status information on snapshots in progress.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def status(params = {})
        response = client.get "/_snapshot{/repository}/_status", update_params(params, action: "repository.status", rest_api: "snapshot.status")
        response.body
      end

      # Update the repository.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # body   - The repository type and settings as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def update(body, params = {})
        response = client.put "/_snapshot/{repository}", update_params(params, body:, action: "repository.update", rest_api: "snapshot.create_repository")
        response.body
      end

      # Delete the repository.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_repositories
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete "/_snapshot/{repository}", update_params(params, action: "repository.delete", rest_api: "snapshot.delete_repository")
        response.body
      end

      # Provides access to snapshot API commands. These commands will be
      # scoped to this repository and the given snapshot name.
      #
      # snapshot - The snapshot name as a String, or nil for all snapshots.
      #
      # Returns a Snapshot instance.
      def snapshot(snapshot = nil)
        client.snapshot(name, snapshot)
      end
      alias_method :snapshots, :snapshot

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil)
        h = defaults.update params
        h.update overrides unless overrides.nil?
        h
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        { repository: name }
      end
    end
  end
end

```

# lib/elastomer_client/client/rest_api_spec.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Provides access to the versioned REST API specs for Elasticsearch.
    module RestApiSpec

      # Returns an ApiSpec instance for the given Elasticsearcion version. This
      # method will load the ApiSpec version class if it has not already been
      # defined. This prevents bloat by only loading the version specs that are
      # needed.
      #
      # Because of this lazy loading, this method is _not_ thread safe.
      #
      # version - the Elasticsearch version String
      #
      # Returns the requested ApiSpec version if available
      def self.api_spec(version)
        classname = "ApiSpecV#{to_class_version(version)}"
        load_api_spec(version) if !self.const_defined? classname
        self.const_get(classname).new
      end

      # Internal: Load the specific ApiSpec version class for the given version.
      def self.load_api_spec(version)
        path = File.expand_path("../rest_api_spec/api_spec_v#{to_class_version(version)}.rb", __FILE__)
        if File.exist? path
          load path
        else
          raise RuntimeError, "Unsupported REST API spec version: #{version}"
        end
      end

      # Internal: Convert a dotted version String into an underscore format
      # suitable for use in Ruby class names.
      def self.to_class_version(version)
        version.to_s.split(".").slice(0, 2).join("_")
      end
    end
  end
end

require_relative "rest_api_spec/api_spec"
require_relative "rest_api_spec/rest_api"

```

# lib/elastomer_client/client/scroller.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Create a new Scroller instance for scrolling all results from a `query`.
    #
    # query  - The query to scroll as a Hash or a JSON encoded String
    # opts   - Options Hash
    #   :index  - the name of the index to search
    #   :type   - the document type to search
    #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
    #   :size   - the number of documents per shard to fetch per scroll
    #
    # Examples
    #
    #   scroll = client.scroll('{"query":{"match_all":{}}}', index: 'test')
    #   scroll.each_document do |document|
    #     document['_id']
    #     document['_source']
    #   end
    #
    # Returns a new Scroller instance
    def scroll(query, opts = {})
      Scroller.new(self, query, opts)
    end

    # Create a new Scroller instance for scrolling all results from a `query`
    # via "scan" semantics by sorting by _doc.
    #
    # query  - The query to scan as a Hash or a JSON encoded String
    # opts   - Options Hash
    #   :index  - the name of the index to search
    #   :type   - the document type to search
    #   :scroll - the keep alive time of the scrolling request (5 minutes by default)
    #   :size   - the number of documents per shard to fetch per scroll
    #
    # Examples
    #
    #   scan = client.scan('{"query":{"match_all":{}}}', index: 'test')
    #   scan.each_document do |document|
    #     document['_id']
    #     document['_source']
    #   end
    #
    # Returns a new Scroller instance
    def scan(query, opts = {})
      Scroller.new(self, add_sort_by_doc(query), opts)
    end

    # Begin scrolling a query.
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
    #
    # opts   - Options Hash
    #   :body        - the query to scroll as a Hash or JSON encoded String
    #   :index       - the name of the index to search
    #   :type        - the document type to search
    #   :scroll      - the keep alive time of the scrolling request (5 minutes by default)
    #   :size        - the number of documents per shard to fetch per scroll
    #
    # Examples
    #
    #   h = client.start_scroll(body: '{"query":{"match_all":{}},"sort":{"created":"desc"}}', index: 'test')
    #   scroll_id = h['_scroll_id']
    #   h['hits']['hits'].each { |doc| ... }
    #
    #   h = client.continue_scroll(scroll_id)
    #   scroll_id = h['_scroll_id']
    #   h['hits']['hits'].each { |doc| ... }
    #
    #   # repeat until there are no more hits
    #
    # Returns the response body as a Hash.
    def start_scroll(opts = {})
      opts = opts.merge action: "search.start_scroll", rest_api: "search"
      opts.delete(:type) if version_support.es_version_8_plus?
      response = get "{/index}{/type}/_search", opts
      response.body
    end

    # Continue scrolling a query.
    # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
    #
    # scroll_id - The current scroll ID as a String
    # scroll    - The keep alive time of the scrolling request (5 minutes by default)
    #
    # Examples
    #
    #   scroll_id = client.start_scroll(body: '{"query":{"match_all":{}}}', index: 'test')['_scroll_id']
    #
    #   h = client.continue_scroll scroll_id   # scroll to get the next set of results
    #   scroll_id = h['_scroll_id']            # and store the scroll_id to use later
    #
    #   h = client.continue_scroll scroll_id   # scroll again to get the next set of results
    #   scroll_id = h['_scroll_id']            # and store the scroll_id to use later
    #
    #   # repeat until the results are empty
    #
    # Returns the response body as a Hash.
    def continue_scroll(scroll_id, scroll = "5m")
      response = get "/_search/scroll", body: {scroll_id:}, scroll:, action: "search.scroll", rest_api: "scroll"
      response.body
    rescue RequestError => err
      if err.error && err.error["caused_by"]["type"] == "search_context_missing_exception"
        raise SearchContextMissing, "No search context found for scroll ID #{scroll_id.inspect}"
      else
        raise err
      end
    end

    # Delete one or more scroll IDs.
    # see https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html#_clear_scroll_api
    #
    # scroll_id - One or more scroll IDs
    #
    # Returns the response body as a Hash.
    def clear_scroll(scroll_ids)
      response = delete "/_search/scroll", body: {scroll_id: Array(scroll_ids)}, action: "search.clear_scroll", rest_api: "clear_scroll"
      response.body
    end

    # Internal: Add sort by doc to query.
    #
    # Raises an exception if the query contains a sort already.
    # Returns the query as a hash
    def add_sort_by_doc(query)
      if query.nil?
        query = {}
      elsif query.is_a? String
        query = MultiJson.load(query)
      end

      if query.has_key? :sort
        raise ArgumentError, "Query cannot contain a sort (found sort '#{query[:sort]}' in query: #{query})"
      end

      query.merge(sort: [:_doc])
    end

    DEFAULT_OPTS = {
      index:   nil,
      type:    nil,
      scroll:  "5m",
      size:    50,
    }.freeze

    class Scroller
      # Create a new scroller that can be used to iterate over all the documents
      # returned by the `query`. The Scroller supports both the 'scan' and the
      # 'scroll' search types.
      #
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html
      # and https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-search-type.html#scan
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # query  - The query to scroll as a Hash or a JSON encoded String
      # opts   - Options Hash
      #   :index       - the name of the index to search
      #   :type        - the document type to search
      #   :scroll      - the keep alive time of the scrolling request (5 minutes by default)
      #   :size        - the number of documents per shard to fetch per scroll
      #
      # Examples
      #
      #   scan = Scroller.new(client, {query: {match_all: {}}}, index: 'test-1')
      #   scan.each_document { |doc|
      #     doc['_id']
      #     doc['_source']
      #   }
      #
      def initialize(client, query, opts = {})
        @client = client

        @opts = DEFAULT_OPTS.merge({ body: query }).merge(opts)

        @scroll_id = nil
        @offset = 0
      end

      attr_reader :client, :query, :scroll_id

      # Iterate over all the search results from the scan query.
      #
      # block  - The block will be called for each set of matching documents
      #          returned from executing the scan query.
      #
      # Yields a hits Hash containing the 'total' number of hits, current
      # 'offset' into that total, and the Array of 'hits' document Hashes.
      #
      # Examples
      #
      #   scan.each do |hits|
      #     hits['total']
      #     hits['offset']
      #     hits['hits'].each { |document| ... }
      #   end
      #
      # Returns this Scroller instance.
      def each
        loop do
          body = do_scroll

          hits = body["hits"]
          break if hits["hits"].empty?

          hits["offset"] = @offset
          @offset += hits["hits"].length

          yield hits
        end

        self
      ensure
        clear!
      end

      # Iterate over each document from the scan query. This method is just a
      # convenience wrapper around the `each` method; it iterates the Array of
      # documents and passes them one by one to the block.
      #
      # block  - The block will be called for each document returned from
      #          executing the scan query.
      #
      # Yields a document Hash.
      #
      # Examples
      #
      #   scan.each_document do |document|
      #     document['_id']
      #     document['_source']
      #   end
      #
      # Returns this Scroller instance.
      def each_document(&block)
        each { |hits| hits["hits"].each(&block) }
      end

      # Terminate the scroll query. This will remove the search context from the
      # cluster and no further documents can be returned by this Scroller
      # instance.
      #
      # Returns nil if the `scroll_id` is not valid; returns the response body if
      # the `scroll_id` was cleared.
      def clear!
        return if scroll_id.nil?
        client.clear_scroll(scroll_id)
      rescue ::ElastomerClient::Client::IllegalArgument
        nil
      end

      # Internal: Perform the actual scroll requests. This method wil call out
      # to the `Client#start_scroll` and `Client#continue_scroll` methods while
      # keeping track of the `scroll_id` internally.
      #
      # Returns the response body as a Hash.
      def do_scroll
        if scroll_id.nil?
          body = client.start_scroll(@opts)
          if body["hits"]["hits"].empty?
            @scroll_id = body["_scroll_id"]
            return do_scroll
          end
        else
          body = client.continue_scroll(scroll_id, @opts[:scroll])
        end

        @scroll_id = body["_scroll_id"]
        body
      end

    end  # Scroller
  end  # Client
end  # ElastomerClient

```

# lib/elastomer_client/client/snapshot.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Provides access to snapshot API commands.
    #
    # repository - The name of the repository as a String
    # name       - The name of the snapshot as a String
    #
    # Returns a Snapshot instance.
    def snapshot(repository = nil, name = nil)
      Snapshot.new self, repository, name
    end

    class Snapshot
      # Create a new snapshot object for making API requests that pertain to
      # creating, restoring, deleting, and retrieving snapshots.
      #
      # client     - ElastomerClient::Client used for HTTP requests to the server
      # repository - The name of the repository as a String. Cannot be nil if
      #              snapshot name is not nil.
      # name       - The name of the snapshot as a String
      def initialize(client, repository = nil, name = nil)
        @client     = client
        # don't allow nil repository if snapshot name is not nil
        @repository = @client.assert_param_presence(repository, "repository name") unless repository.nil? && name.nil?
        @name       = @client.assert_param_presence(name, "snapshot name") unless name.nil?
      end

      attr_reader :client, :repository, :name

      # Check for the existence of the snapshot.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # params - Parameters Hash
      #
      # Returns true if the snapshot exists
      def exists?(params = {})
        response = client.get "/_snapshot/{repository}/{snapshot}", update_params(params, action: "snapshot.exists", rest_api: "snapshot.get")
        response.success?
      rescue ElastomerClient::Client::Error => err
        if err.error && err.error.dig("root_cause", 0, "type") == "snapshot_missing_exception"
          false
        else
          raise err
        end
      end
      alias_method :exist?, :exists?

      # Create the snapshot.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # body   - The snapshot options as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def create(body = {}, params = {})
        response = client.put "/_snapshot/{repository}/{snapshot}", update_params(params, body:, action: "snapshot.create", rest_api: "snapshot.create")
        response.body
      end

      # Get snapshot progress information.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def get(params = {})
        # Set snapshot name or we'll get the repository instead
        snapshot = name || "_all"
        response = client.get "/_snapshot/{repository}/{snapshot}", update_params(params, snapshot:, action: "snapshot.get", rest_api: "snapshot.get")
        response.body
      end

      # Get detailed snapshot status.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def status(params = {})
        response = client.get "/_snapshot{/repository}{/snapshot}/_status", update_params(params, action: "snapshot.status", rest_api: "snapshot.status")
        response.body
      end

      # Restore the snapshot.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # body   - The restore options as a Hash or a JSON encoded String
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def restore(body = {}, params = {})
        response = client.post "/_snapshot/{repository}/{snapshot}/_restore", update_params(params, body:, action: "snapshot.restore", rest_api: "snapshot.restore")
        response.body
      end

      # Delete the snapshot.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html#_snapshot
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete "/_snapshot/{repository}/{snapshot}", update_params(params, action: "snapshot.delete", rest_api: "snapshot.delete")
        response.body
      end

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil)
        h = defaults.update params
        h.update overrides unless overrides.nil?
        h
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        { repository:, snapshot: name }
      end
    end
  end
end

```

# lib/elastomer_client/client/tasks.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Returns a Tasks instance for querying the cluster bound to this client for
    # metadata about internal tasks in flight, and to submit administrative
    # requests (like cancellation) concerning those tasks.
    #
    # Returns a new Tasks object associated with this client
    def tasks
      Tasks.new(self)
    end

    class Tasks

      # Create a new Tasks for introspecting on internal cluster activity.
      # More context: https://www.elastic.co/guide/en/elasticsearch/reference/5.6/tasks.html
      #
      # client     - ElastomerClient::Client used for HTTP requests to the server
      #
      # Raises IncompatibleVersionException if caller attempts to access Tasks API on ES version < 5.0.0
      def initialize(client)
        @client = client
      end

      attr_reader :client

      # Fetch results from the generic _tasks endpoint.
      #
      # params - Hash of request parameters, including:
      #
      # Examples
      #
      #   tasks.get
      #   tasks.get nodes: "DmteLdw1QmSgW3GZmjmoKA,DmteLdw1QmSgW3GZmjmoKB", actions: "cluster:*", detailed: true
      #
      # Examples (ES 5+ only)
      #
      #   tasks.get group_by: "parents"
      #   tasks.get group_by: "parents", actions: "*reindex", ...
      #
      # Returns the response body as a Hash
      def get(params = {})
        response = client.get "/_tasks", params.merge(action: "tasks.list", rest_api: "tasks.list")
        response.body
      end

      # Fetch results from the _tasks endpoint for a particular cluster node and task ID.
      # NOTE: the API docs note the behavior wrong for this call; "task_id:<task_id>" is really "<node_id>:<task_id>"
      # where "node_id" is a value from the "nodes" hash returned from the /_tasks endpoint, and "task_id" is
      # from the "tasks" child hash of any of the "nodes" entries of the /_tasks endpoint
      #
      # node_id - the name of the ES cluster node hosting the target task
      # task_id - the numerical ID of the task to return data about in the response
      # params  - Hash of request parameters to include
      #
      # Examples
      #
      #  tasks.get_by_id "DmteLdw1QmSgW3GZmjmoKA", 123
      #  tasks.get_by_id "DmteLdw1QmSgW3GZmjmoKA", 456, pretty: true
      #
      # Returns the response body as a Hash
      def get_by_id(node_id, task_id, params = {})
        raise ArgumentError, "invalid node ID provided: #{node_id.inspect}" if node_id.to_s.empty?
        raise ArgumentError, "invalid task ID provided: #{task_id.inspect}" unless task_id.is_a?(Integer)

        # in this API, the task ID is included in the path, not as a request parameter.
        response = client.get "/_tasks/{task_id}", params.merge(task_id: "#{node_id}:#{task_id}", action: "tasks.get", rest_api: "tasks.get")
        response.body
      end

      # Fetch task details for all child tasks of the specified parent task.
      # NOTE: the API docs note the behavior wrong for this call: "parentTaskId:<task_id>"
      # is not the correct syntax for the parent_task_id param value. The correct
      # value syntax is "<parent_node_id>:<parent_task_id>"
      #
      # parent_node_id - ID of the node the parent task is hosted by
      # parent_task_id - ID of a parent task who's child tasks' data will be returned in the response
      # params         - Hash of request parameters to include
      #
      # Examples
      #
      #   tasks.get_by_parent_id "DmteLdw1QmSgW3GZmjmoKA", 123
      #   tasks.get_by_parent_id "DmteLdw1QmSgW3GZmjmoKB", 456, :detailed => true
      #
      # Returns the response body as a Hash
      def get_by_parent_id(parent_node_id, parent_task_id, params = {})
        raise ArgumentError, "invalid parent node ID provided: #{parent_node_id.inspect}" if node_id.to_s.empty?
        raise ArgumentError, "invalid parent task ID provided: #{parent_task_id.inspect}" unless parent_task_id.is_a?(Integer)

        parent_task_id = "#{parent_node_id}:#{parent_task_id}"
        params = params.merge(action: "tasks.parent", rest_api: "tasks.list")

        params[:parent_task_id] = parent_task_id

        response = client.get "/_tasks", params
        response.body
      end

      # Wait for the specified amount of time (10 seconds by default) for some task(s) to complete.
      # Filters for task(s) to wait upon using same filter params as Tasks#get(params)
      #
      # timeout - maximum time to wait for target task to complete before returning, example: "5s"
      # params  - Hash of request params to include (mostly task filters in this context)
      #
      # Examples
      #
      # tasks.wait_for "5s", actions: "*health"
      # tasks.wait_for("30s", actions: "*reindex", nodes: "DmteLdw1QmSgW3GZmjmoKA,DmteLdw1QmSgW3GZmjmoKB")
      #
      # Returns the response body as a Hash when timeout expires or target tasks complete
      # COMPATIBILITY WARNING: the response body differs between ES versions for this API
      def wait_for(timeout = "10s", params = {})
        self.get params.merge(wait_for_completion: true, timeout:)
      end

      # Wait for the specified amount of time (10 seconds by default) for some task(s) to complete.
      # Filters for task(s) to wait upon using same IDs and filter params as Tasks#get_by_id(params)
      #
      # node_id - the ID of the node on which the target task is hosted
      # task_id - the ID of the task to wait on
      # timeout - time for call to await target tasks completion before returning
      # params  - Hash of request params to include (mostly task filters in this context)
      #
      # Examples
      #
      # tasks.wait_by_id "DmteLdw1QmSgW3GZmjmoKA", 123, "15s"
      # tasks.wait_by_id "DmteLdw1QmSgW3GZmjmoKA", 456, "30s", actions: "*search"
      #
      # Returns the response body as a Hash when timeout expires or target tasks complete
      def wait_by_id(node_id, task_id, timeout = "10s", params = {})
        raise ArgumentError, "invalid node ID provided: #{node_id.inspect}" if node_id.to_s.empty?
        raise ArgumentError, "invalid task ID provided: #{task_id.inspect}" unless task_id.is_a?(Integer)

        self.get_by_id(node_id, task_id, params.merge(wait_for_completion: true, timeout:))
      end

      # Cancels a task running on a particular node.
      # NOTE: the API docs note the behavior wrong for this call; "task_id:<task_id>" is really "<node_id>:<task_id>"
      # where "node_id" is a value from the "nodes" hash returned from the /_tasks endpoint, and "task_id" is
      # from the "tasks" child hash of any of the "nodes" entries of the /_tasks endpoint
      #
      # node_id         - the ES node hosting the task to be cancelled
      # task_id         - ID of the task to be cancelled
      # params          - Hash of request parameters to include
      #
      # Examples
      #
      #   tasks.cancel_by_id "DmteLdw1QmSgW3GZmjmoKA", 123
      #   tasks.cancel_by_id "DmteLdw1QmSgW3GZmjmoKA", 456, pretty: true
      #
      # Returns the response body as a Hash
      def cancel_by_id(node_id, task_id, params = {})
        raise ArgumentError, "invalid node ID provided: #{node_id.inspect}" if node_id.to_s.empty?
        raise ArgumentError, "invalid task ID provided: #{task_id.inspect}" unless task_id.is_a?(Integer)

        self.cancel(params.merge(task_id: "#{node_id}:#{task_id}"))
      end

      # Cancels a task or group of tasks using various filtering parameters.
      #
      # params - Hash of request parameters to include
      #
      # Examples
      #
      #   tasks.cancel actions: "*reindex"
      #   tasks.cancel actions: "*search", nodes: "DmteLdw1QmSgW3GZmjmoKA,DmteLdw1QmSgW3GZmjmoKB,DmteLdw1QmSgW3GZmjmoKC"
      #
      # Returns the response body as a Hash
      def cancel(params = {})
        response = client.post "/_tasks{/task_id}/_cancel", params.merge(action: "tasks.cancel", rest_api: "tasks.cancel")
        response.body
      end

    end
  end
end

```

# lib/elastomer_client/client/template.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client

    # Returns a Template instance.
    def template(name)
      Template.new self, name
    end


    class Template

      # Create a new template client for making API requests that pertain to
      # template management.
      #
      # client - ElastomerClient::Client used for HTTP requests to the server
      # name   - The name of the template as a String
      #
      def initialize(client, name)
        @client = client
        @name   = name
      end

      attr_reader :client, :name

      # Returns true if the template already exists on the cluster.
      def exists?(params = {})
        response = client.head "/_template/{template}", update_params(params, action: "template.exists", rest_api: "indices.exists_template")
        response.success?
      end
      alias_method :exist?, :exists?

      # Get the template from the cluster.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html#getting
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def get(params = {})
        response = client.get "/_template/{template}", update_params(params, action: "template.get", rest_api: "indices.get_template")
        response.body
      end

      # Create the template on the cluster.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html
      #
      # template - The template as a Hash or a JSON encoded String
      # params   - Parameters Hash
      #
      # Returns the response body as a Hash
      def create(template, params = {})
        response = client.put "/_template/{template}", update_params(params, body: template, action: "template.create", rest_api: "indices.put_template")
        response.body
      end

      # Delete the template from the cluster.
      # See https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html#delete
      #
      # params - Parameters Hash
      #
      # Returns the response body as a Hash
      def delete(params = {})
        response = client.delete "/_template/{template}", update_params(params, action: "template.delete", rest_api: "indices.delete_template")
        response.body
      end

      # Internal: Add default parameters to the `params` Hash and then apply
      # `overrides` to the params if any are given.
      #
      # params    - Parameters Hash
      # overrides - Optional parameter overrides as a Hash
      #
      # Returns a new params Hash.
      def update_params(params, overrides = nil)
        h = defaults.update params
        h.update overrides unless overrides.nil?
        h
      end

      # Internal: Returns a Hash containing default parameters.
      def defaults
        { template: name }
      end
    end
  end
end

```

# lib/elastomer_client/client/update_by_query.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class Client
    # Update documents based on a query using the Elasticsearch _update_by_query API.
    #
    # query  - The query body as a Hash
    # params - Parameters Hash
    #
    # Examples
    #
    #   # request body query
    #   update_by_query({
    #     "script": {
    #       "source": "ctx._source.count++",
    #       "lang": "painless"
    #     },
    #     "query": {
    #       "term": {
    #         "user.id": "kimchy"
    #       }
    #     }
    #   })
    #
    # See https://www.elastic.co/guide/en/elasticsearch/reference/8.7/docs-update-by-query.html
    #
    # Returns a Hash containing the _update_by_query response body.
    def update_by_query(query, parameters = {})
      UpdateByQuery.new(self, query, parameters).execute
    end

    class UpdateByQuery
      attr_reader :client, :query, :parameters

      def initialize(client, query, parameters)
        @client = client
        @query = query
        @parameters = parameters
      end

      def execute
        # TODO: Require index parameter. type is optional.
        updated_params = parameters.merge(body: query, action: "update_by_query", rest_api: "update_by_query")
        updated_params.delete(:type) if client.version_support.es_version_8_plus?
        response = client.post("/{index}{/type}/_update_by_query", updated_params)
        response.body
      end
    end
  end
end

```

# lib/elastomer_client/core_ext/time.rb

```rb
# frozen_string_literal: true

require "time"

class Time
  def to_json(ignore = nil)
    %Q["#{self.iso8601(3)}"]
  end
end

```

# lib/elastomer_client/middleware/compress.rb

```rb
# frozen_string_literal: true
require "stringio"

module ElastomerClient
  module Middleware
    # Request middleware that compresses request bodies with GZip for supported
    # versions of Elasticsearch.
    #
    # It will only compress when there is a request body that is a String. This
    # middleware should be inserted after JSON serialization.
    class Compress < Faraday::Middleware
      CONTENT_ENCODING = "Content-Encoding"
      GZIP = "gzip"
      # An Ethernet packet can hold 1500 bytes. No point in compressing anything smaller than that (plus some wiggle room).
      MIN_BYTES_FOR_COMPRESSION = 1400

      attr_reader :compression

      # options - The Hash of "keyword" arguments.
      #           :compression - the compression level (0-9, default Zlib::DEFAULT_COMPRESSION)
      def initialize(app, options = {})
        super(app)
        @compression = options[:compression] || Zlib::DEFAULT_COMPRESSION
      end

      def call(env)
        if body = env[:body]
          if body.is_a?(String) && body.bytesize > MIN_BYTES_FOR_COMPRESSION
            output = StringIO.new
            output.set_encoding("BINARY")
            gz = Zlib::GzipWriter.new(output, compression, Zlib::DEFAULT_STRATEGY)
            gz.write(env[:body])
            gz.close
            env[:body] = output.string
            env[:request_headers][CONTENT_ENCODING] = GZIP
          end
        end

        @app.call(env)
      end
    end
  end
end

Faraday::Request.register_middleware(elastomer_compress: ElastomerClient::Middleware::Compress)

```

# lib/elastomer_client/middleware/encode_json.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  module Middleware
    # Request middleware that encodes the body as JSON.
    #
    # Processes only requests with matching Content-type or those without a type.
    # If a request doesn't have a type but has a body, it sets the Content-type
    # to JSON MIME-type.
    #
    # Doesn't try to encode bodies that already are in string form.
    class EncodeJson < Faraday::Middleware
      CONTENT_TYPE = "Content-Type".freeze
      MIME_TYPE    = "application/json".freeze

      def call(env)
        match_content_type(env) do |data|
          env[:body] = encode data
        end
        @app.call env
      end

      def encode(data)
        MultiJson.dump data
      end

      def match_content_type(env)
        add_content_type!(env)
        if process_request?(env)
          yield env[:body] unless env[:body].respond_to?(:to_str)
        end
      end

      def process_request?(env)
        type = request_type(env)
        has_body?(env) && (type.empty? || type == MIME_TYPE)
      end

      def has_body?(env)
        (body = env[:body]) && !(body.respond_to?(:to_str) && body.empty?)
      end

      def request_type(env)
        type = env[:request_headers][CONTENT_TYPE].to_s
        type = type.split(";", 2).first if type.index(";")
        type
      end

      def add_content_type!(env)
        method = env[:method]
        if method == :put || method == :post || has_body?(env)
          env[:request_headers][CONTENT_TYPE] ||= MIME_TYPE
        end
      end
    end
  end
end

Faraday::Request.register_middleware \
  encode_json: ElastomerClient::Middleware::EncodeJson

```

# lib/elastomer_client/middleware/limit_size.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  module Middleware

    # Request middleware that raises an exception if the request body exceeds a
    # `max_request_size`.
    class LimitSize < Faraday::Middleware

      def initialize(app = nil, options = {})
        super(app)
        @max_request_size = options.fetch(:max_request_size)
      end

      attr_reader :max_request_size

      def call(env)
        if body = env[:body]
          if body.is_a?(String) && body.bytesize > max_request_size
            raise ::ElastomerClient::Client::RequestSizeError,
              "Request of size `#{body.bytesize}` exceeds the maximum requst size: #{max_request_size}"
          end
        end
        @app.call(env)
      end

    end
  end
end

Faraday::Request.register_middleware \
  limit_size: ElastomerClient::Middleware::LimitSize

```

# lib/elastomer_client/middleware/opaque_id.rb

```rb
# frozen_string_literal: true

require "securerandom"

module ElastomerClient
  module Middleware

    # This Faraday middleware implements the "X-Opaque-Id" request / response
    # headers for Elasticsearch. The X-Opaque-Id header, when provided on the
    # request header, will be returned as a header in the response. This is
    # useful in environments which reuse connections to ensure that cross-talk
    # does not occur between two requests.
    #
    # The SecureRandom lib is used to generate a UUID string for each request.
    # This value is used as the content for the "X-Opaque-Id" header. If the
    # value is different between the request and the response, then an
    # `ElastomerClient::Client::OpaqueIdError` is raised. In this case no response
    # will be returned.
    #
    # See [Elasticsearch "X-Opaque-Id"
    # header](https://github.com/elasticsearch/elasticsearch/issues/1202)
    # for more details.
    class OpaqueId < ::Faraday::Middleware
      X_OPAQUE_ID = "X-Opaque-Id".freeze
      COUNTER_MAX = 2**32 - 1

      # Faraday middleware implementation.
      #
      # env - Faraday environment Hash
      #
      # Returns the environment Hash
      def call(env)
        uuid = generate_uuid.freeze
        env[:request_headers][X_OPAQUE_ID] = uuid

        @app.call(env).on_complete do |renv|
          response_uuid = renv[:response_headers][X_OPAQUE_ID]
          # Don't raise OpaqueIdError if the response is a 5xx
          if !response_uuid.nil? && uuid != response_uuid && renv.status < 500
            raise ::ElastomerClient::Client::OpaqueIdError,
                  "Conflicting 'X-Opaque-Id' headers: request #{uuid.inspect}, response #{response_uuid.inspect}"
          end
        end
      end

      # Generate a UUID using the built-in SecureRandom class. This can be a
      # little slow at times, so we will reuse the same UUID and append an
      # incrementing counter.
      #
      # Returns the UUID string.
      def generate_uuid
        t = Thread.current

        unless t.key? :opaque_id_base
          t[:opaque_id_base]    = (SecureRandom.urlsafe_base64(12) + "%08x").freeze
          t[:opaque_id_counter] = -1
        end

        t[:opaque_id_counter] += 1
        t[:opaque_id_counter] = 0 if t[:opaque_id_counter] > COUNTER_MAX
        t[:opaque_id_base] % t[:opaque_id_counter]
      end

    end  # OpaqueId
  end  # Middleware

  # Error raised when a conflict is detected between the UUID sent in the
  # 'X-Opaque-Id' request header and the one received in the response header.
  Client::OpaqueIdError = Class.new Client::Error

end  # ElastomerClient

Faraday::Request.register_middleware \
  opaque_id: ElastomerClient::Middleware::OpaqueId

```

# lib/elastomer_client/middleware/parse_json.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  module Middleware

    # Parse response bodies as JSON.
    class ParseJson < Faraday::Middleware
      CONTENT_TYPE = "Content-Type".freeze
      MIME_TYPE    = "application/json".freeze

      def call(environment)
        @app.call(environment).on_complete do |env|
          if process_response?(env)
            env[:body] = parse env[:body]
          end
        end
      end

      # Parse the response body.
      def parse(body)
        MultiJson.load(body) if body.respond_to?(:to_str) && !body.strip.empty?
      rescue StandardError, SyntaxError => e
        raise Faraday::ParsingError, e
      end

      def process_response?(env)
        type = response_type(env)
        type.empty? || type == MIME_TYPE
      end

      def response_type(env)
        type = env[:response_headers][CONTENT_TYPE].to_s
        type = type.split(";", 2).first if type.index(";")
        type
      end
    end
  end
end

Faraday::Response.register_middleware \
  parse_json: ElastomerClient::Middleware::ParseJson

```

# lib/elastomer_client/notifications.rb

```rb
# frozen_string_literal: true

require "active_support"
require "active_support/notifications"
require "securerandom"
require "elastomer_client/client"

module ElastomerClient

  # So you want to get notifications from your Elasticsearch client? Well,
  # you've come to the right place!
  #
  #   require 'elastomer_client/notifications'
  #
  # Requiring this module will add ActiveSupport notifications to all
  # Elasticsearch requests. To subscribe to those requests ...
  #
  #   ActiveSupport::Notifications.subscribe('request.client.elastomer') do |name, start_time, end_time, _, payload|
  #     duration = end_time - start_time
  #     $stderr.puts '[%s] %s %s (%.3f)' % [payload[:status], payload[:index], payload[:action], duration]
  #   end
  #
  # The payload contains the following bits of information:
  #
  # * :index  - index name (if any)
  # * :type   - document type (if any)
  # * :action - the action being performed
  # * :url    - request URL
  # * :method - request method (:head, :get, :put, :post, :delete)
  # * :status - response status code
  #
  # If you want to use your own notifications service then you will need to
  # let ElastomerClient know by setting the `service` here in the Notifications
  # module. The service should adhere to the ActiveSupport::Notifications
  # specification.
  #
  #   ElastomerClient::Notifications.service = your_own_service
  #
  module Notifications

    class << self
      attr_accessor :service
    end

    # The name to subscribe to for notifications
    NAME = "request.client.elastomer".freeze

    # Internal: Execute the given block and provide instrumentation info to
    # subscribers. The name we use for subscriptions is
    # `request.client.elastomer` and a supplemental payload is provided with
    # more information about the specific Elasticsearch request.
    #
    # path   - The full request path as a String
    # body   - The request body as a String or `nil`
    # params - The request params Hash
    # block  - The block that will be instrumented
    #
    # Returns the response from the block
    def instrument(path, body, params)
      payload = {
        index: params[:index],
        type: params[:type],
        action: params[:action],
        context: params[:context],
        request_body: body,
        body:   # for backwards compatibility
      }

      ::ElastomerClient::Notifications.service.instrument(NAME, payload) do
        response = yield
        payload[:url]           = response.env[:url]
        payload[:method]        = response.env[:method]
        payload[:status]        = response.status
        payload[:response_body] = response.body
        response
      end
    end
  end

  # use ActiveSupport::Notifications as the default instrumentation service
  Notifications.service = ActiveSupport::Notifications

  # inject our instrument method into the Client class
  class Client
    remove_method :instrument
    include ::ElastomerClient::Notifications
  end
end

```

# lib/elastomer_client/version_support.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  class VersionSupport

    attr_reader :version

    # version - an Elasticsearch version string e.g., 5.6.6 or 9.x.x
    #
    # Raises ArgumentError if version is unsupported.
    def initialize(version)
      if version < "5.0" || version >= "10.0"
        raise ArgumentError, "Elasticsearch version #{version} is not supported by elastomer-client"
      end

      @version = version
    end

    # Returns true if Elasticsearch version is 9.x or higher.
    def es_version_9_plus?
      version >= "9.0.0"
    end

    # Returns true if Elasticsearch version is 8.x or higher.
    def es_version_8_plus?
      version >= "8.0.0"
    end
  end
end

```

# lib/elastomer_client/version.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  VERSION = "6.2.1"

  def self.version
    VERSION
  end
end

```

# LICENSE.txt

```txt
Copyright (c) 2013 GitHub Inc.

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

```

# Rakefile

```
# frozen_string_literal: true

require "bundler/gem_tasks"

require "rake/testtask"

Rake::TestTask.new do |t|
  t.test_files = FileList["test/**/*_test.rb"]
end

task default: :test

namespace :actions do
  desc "list valid actions"
  task :list do
    # there are two distinct :action declarations we need to find
    # the regular expressions below capture both
    #
    #   [:action] = 'some.value'
    #   :action => 'some.value'
    #
    list = %x(grep '\\[\\?:action\\]\\?\\s\\+=' `find lib -name '*.rb'`).split("\n")
    list.map! do |line|
      m = /\A.*?\[?:action\]?\s+=>?\s+'(.*?)'.*\Z/.match line
      m.nil? ? nil : m[1]
    end

    list.compact.sort.uniq.each do |action|
      STDOUT.puts "- #{action}"
    end
  end
end

```

# script/bootstrap

```
#!/bin/sh
set -ex

cd "$(dirname "$0:a")/.."
if bundle check 1>/dev/null 2>&1; then
    echo "Gem environment up-to-date"
else
    echo "Installing gem dependencies"
    exec bundle install "$@"
    exec bundle binstubs --all
fi

```

# script/console

```
#!/usr/bin/env ruby
# frozen_string_literal: true

require "irb"
require "rubygems"
require "bundler/setup"

$LOAD_PATH.unshift "lib"
require "elastomer_client/client"

IRB.start

```

# script/generate-rest-api-spec

```
#!/usr/bin/env ruby
# frozen_string_literal: true

# Usage:
#
#   script/generate-rest-api-spec <elasticsearch-version>
#
# Use this script to generate a REST API spec for the given
# `elasticserach-version`. This will create a new `ApiSpec` class configured
# to validate the request parameters for the particular Elasticsearch version.

require "erb"
require "rubygems"
require "bundler/setup"

$LOAD_PATH.unshift "lib"
require "elastomer_client/client"
require "elastomer_client/version_support"

class RestApiSpecGenerator
  WORKING_DIR = "vendor/elasticsearch"

  attr_reader :version, :short_version, :class_version

  def initialize(version = "8.13")
    @version = version

    sliced = @version.split(".").slice(0, 2)
    @short_version = sliced.join(".")
    @class_version = sliced.join("_")

    @version_support = ElastomerClient::VersionSupport.new(version)
  end

  # Setup the working directory and generate the Ruby API spec for the
  # elasticsearch version.
  def run
    setup
    File.open(ruby_spec_filename, "w") do |fd|
      fd.puts ERB.new(DATA.read, trim_mode: "-").result(binding)
    end
  ensure
    reset
  end

  # The name of the Ruby API spec file for this particular Elasticsearch version.
  def ruby_spec_filename
    "lib/elastomer_client/client/rest_api_spec/api_spec_v#{class_version}.rb"
  end

  # Returns true if the elasticserach working directory exists.
  def working_dir_exists?
    File.directory?(WORKING_DIR) && File.exist?(WORKING_DIR)
  end

  # Iterate over each of the REST API specs yield the name and the descriptor
  # hash for that particular API spec.
  def each_api
    Dir.glob("#{WORKING_DIR}/rest-api-spec/src/main/resources/rest-api-spec/api/*.json").sort.each do |filename|
      next if filename =~ /\/_common\.json\Z/

      hash = MultiJson.load(File.read(filename))
      key = hash.keys.first
      value = hash.values.first
      yield(key, value)
    end
  end

  # Iterate over each of the common request parameters and yield them as key /
  # value pairs.
  def each_common
    filename = "#{WORKING_DIR}/rest-api-spec/src/main/resources/rest-api-spec/api/_common.json"
    if File.exist? filename
      hash = MultiJson.load(File.read(filename))
      hash["params"].each { |k, v| yield(k, v) }
    end
  end

  def generate_documentation(data)
    if @version_support.es_version_8_plus?
      data["documentation"]["url"].to_s
    else
      data["documentation"].to_s
    end
  end

  def generate_methods(data)
    if @version_support.es_version_8_plus?
      data["url"]["paths"].map { |h| h["methods"] }.flatten.uniq
    else
      Array(data["methods"]).to_s
    end
  end

  def generate_path(url)
    if @version_support.es_version_8_plus?
      url["paths"].map { |h| h["path"] }.flatten.uniq.first
    else
      url["path"]
    end
  end

  def generate_paths(url)
    if @version_support.es_version_8_plus?
      url["paths"].map { |h| h["path"] }.flatten.uniq
    else
      Array(url["paths"]).to_s
    end
  end

  def generate_parts(url)
    if @version_support.es_version_8_plus?
      url["paths"].map { |h| h["parts"] }.compact.reduce({}, :merge)
    else
      url["parts"]
    end
  end

  def generate_params(data)
    if @version_support.es_version_8_plus?
      data["params"]
    else
      data["url"]["params"]
    end
  end


  # Perform a sparse checkout of the elasticsearch git repository and then check
  # out the branch corresponding to the ES version passed to this script.
  def setup
    if !working_dir_exists?
      system <<-SH
        mkdir -p #{WORKING_DIR} &&
        cd #{WORKING_DIR} &&
        git init . &&
        git remote add -f origin https://github.com/elastic/elasticsearch.git &&
        git config core.sparsecheckout true &&
        echo /rest-api-spec/src/main/resources/rest-api-spec/api/ >> .git/info/sparse-checkout &&
        git pull origin main
      SH
    end

    system <<-SH
      cd #{WORKING_DIR} &&
      git pull origin main &&
      git checkout -q origin/#{short_version}
    SH
  end

  # Reset the elasticsearch working directory back to the main branch of the
  # git repository.
  def reset
    system <<-SH
      cd #{WORKING_DIR} &&
      git checkout main
    SH
  end
end

puts RestApiSpecGenerator.new(*ARGV).run

__END__
# Generated REST API spec file - DO NOT EDIT!
# Date: <%= Time.now.strftime("%Y-%m-%d") %>
# ES version: <%= version %>

module ElastomerClient::Client::RestApiSpec
  class ApiSpecV<%= class_version %> < ApiSpec
    def initialize
      @rest_apis = {
      <%- each_api do |name,data| -%>
        <%- url = data["url"] -%>
        "<%= name %>" => RestApi.new(
          documentation: "<%= generate_documentation(data) %>",
          methods: <%= generate_methods(data) %>,
          body: <%= data["body"] ? data["body"].to_s : "nil" %>,
          url: {
            path: "<%= generate_path(url) %>",
            paths: <%= generate_paths(url) %>,
<% if (parts = generate_parts(url)) && !parts.empty? -%>
            parts: {
<% parts.each do |k,v| -%>
              "<%= k %>" => <%= v.to_s %>,
<% end -%>
            },
<% end -%>
<% params = generate_params(data) -%>
<% if !params.nil? && !params.empty? -%>
            params: {
<% params.each do |k,v| -%>
              "<%= k %>" => <%= v.to_s %>,
<% end -%>
            }
<% end -%>
          }
        ),
<% end -%>
      }
      @common_params = {
<% each_common do |k,v| -%>
        "<%= k %>" => <%= v.to_s %>,
<% end -%>
      }
      super
    end
  end
end

```

# script/poll-for-es

```
#!/bin/bash
#
# This script will poll the Elasticsearch health endpoint until the cluster
# reaches a yellow state which is good enough for testing. This script will poll
# for up to 30 seconds waiting for Elasticsearch to start. It will give up at
# that time and return a non-zero exit code.

es_port=${ES_PORT:-9200}
count=0

until $(curl -s "localhost:${es_port}/_cluster/health?wait_for_status=yellow&timeout=30s" > /dev/null 2>&1); do
  sleep 0.50
  count=$(($count+1))
  if [ "$count" -gt 60 ]; then
    echo "Timed out waiting for Elasticsearch at localhost:${es_port}"
    exit 1
  fi
done

echo "Elasticsearch is ready at localhost:${es_port}"

```

# test/assertions.rb

```rb
# frozen_string_literal: true

module Minitest::Assertions
  # COMPATIBILITY
  # ES8+ response uses "result" instead of "created"
  def assert_created(response)
    assert $client.version_support.es_version_8_plus? ? response["result"] == "created" : response["created"], "document was not created"
  end

  def assert_acknowledged(response)
    assert response["acknowledged"], "document was not acknowledged"
  end

  def assert_found(response)
    assert response["found"], "document was not found"
  end

  def refute_found(response)
    refute response["found"] || response["exists"], "document was unexpectedly found"
  end

  def assert_bulk_index(item, message = "bulk index did not succeed")
    status = item["index"]["status"]

    assert_equal(201, status, message)
  end

  def assert_bulk_create(item, message = "bulk create did not succeed")
    status = item["create"]["status"]

    assert_equal(201, status, message)
  end

  def assert_bulk_delete(item, message = "bulk delete did not succeed")
    status = item["delete"]["status"]

    assert_equal(200, status, message)
  end

  # COMPATIBILITY
  # ES8+ no longer supports types
  def assert_mapping_exists(response, type, message = "mapping expected to exist, but doesn't")
    mapping =
      if $client.version_support.es_version_8_plus?
        response["mappings"]
      else
        response["mappings"][type]
      end

    refute_nil mapping, message
  end

  # COMPATIBILITY
  # ES8+ no longer supports types
  def assert_property_exists(response, type, property, message = "property expected to exist, but doesn't")
    mapping =
      if response.has_key?("mappings")
        if $client.version_support.es_version_8_plus?
          response["mappings"]
        else
          response["mappings"][type]
        end
      else
        response[type]
      end

    assert mapping["properties"].has_key?(property), message
  end
end

```

# test/client_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../test_helper", __FILE__)
require File.expand_path("../mock_response", __FILE__)
require "elastomer_client/notifications"

describe ElastomerClient::Client do

  it "uses the adapter specified at creation" do
    c = ElastomerClient::Client.new(adapter: :test)

    assert_equal c.connection.builder.adapter, Faraday::Adapter::Test
  end

  it "allows configuring the Faraday when a block is given" do
    assert ElastomerClient::Client.new.connection.builder.handlers.none? { |handler| handler.klass == FaradayMiddleware::Instrumentation }

    c = ElastomerClient::Client.new do |connection|
      assert_kind_of(Faraday::Connection, connection)

      connection.use :instrumentation
    end

    assert c.connection.builder.handlers.any? { |handler| handler.klass == FaradayMiddleware::Instrumentation }
  end

  it "use Faraday's default adapter if none is specified" do
    c = ElastomerClient::Client.new
    adapter = Faraday::Adapter.lookup_middleware(Faraday.default_adapter)

    assert_equal c.connection.builder.adapter, adapter
  end

  it "uses the same connection for all requests" do
    c = $client.connection

    assert_same c, $client.connection
  end

  it "raises an error for unknown HTTP request methods" do
    assert_raises(ArgumentError) { $client.request :foo, "/", {} }
  end

  it "raises an error on 4XX responses with an `error` field" do
    begin
      $client.get "/non-existent-index/_search?q=*:*"

      assert false, "exception was not raised when it should have been"
    rescue ElastomerClient::Client::Error => err
      assert_equal 404, err.status
      assert_match %r/index_not_found_exception/, err.message
    end
  end

  it "raises an error on rejected execution exceptions" do
    rejected_execution_response = {
      error: {
        root_cause: [{
          type: "es_rejected_execution_exception",
          reason: "rejected execution of org.elasticsearch.transport.TransportService$7@5a787cd5 on EsThreadPoolExecutor[bulk, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@1338862c[Running, pool size = 32, active threads = 32, queued tasks = 213, completed tasks = 193082975]]"
        }],
        type: "es_rejected_execution_exception",
        reason: "rejected execution of org.elasticsearch.transport.TransportService$7@5a787cd5 on EsThreadPoolExecutor[bulk, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@1338862c[Running, pool size = 32, active threads = 32, queued tasks = 213, completed tasks = 193082975]]"
      }
    }.to_json

    stub_request(:post, $client.url+"/_bulk").to_return({
      body: rejected_execution_response
    })

    begin
      $client.post "/_bulk"

      assert false, "exception was not raised when it should have been"
    rescue ElastomerClient::Client::RejectedExecutionError => err
      assert_match %r/es_rejected_execution_exception/, err.message
    end
  end

  it "wraps Faraday errors with our own exceptions" do
    error = Faraday::TimeoutError.new("it took too long")
    wrapped = $client.wrap_faraday_error(error, :get, "/_cat/indices")

    assert_instance_of ElastomerClient::Client::TimeoutError, wrapped
    assert_equal "it took too long :: GET /_cat/indices", wrapped.message
  end

  it "handles path expansions" do
    uri = $client.expand_path "/{foo}/{bar}", foo: "_cluster", bar: "health"

    assert_equal "/_cluster/health", uri

    uri = $client.expand_path "{/foo}{/baz}{/bar}", foo: "_cluster", bar: "state"

    assert_equal "/_cluster/state", uri
  end

  it "handles query parameters" do
    uri = $client.expand_path "/_cluster/health", level: "shards"

    assert_equal "/_cluster/health?level=shards", uri
  end

  it "handles query parameters in path and arguments" do
    uri = $client.expand_path "/index/_update_by_query?conflicts=proceed", routing: "1"

    assert_equal "/index/_update_by_query?conflicts=proceed&routing=1", uri
  end

  it "overrides query parameters in path and with arguments" do
    uri = $client.expand_path "/index/_update_by_query?conflicts=proceed&routing=2", routing: "1"

    assert_equal "/index/_update_by_query?conflicts=proceed&routing=1", uri
  end

  it "validates path expansions" do
    assert_raises(ArgumentError) {
      $client.expand_path "/{foo}/{bar}", foo: "_cluster", bar: nil
    }

    assert_raises(ArgumentError) {
      $client.expand_path "/{foo}/{bar}", foo: "_cluster", bar: ""
    }
  end

  it "hides basic_auth and token_auth params from inspection" do
    client_params = $client_params.merge(basic_auth: {
      username: "my_user",
      password: "my_secret_password"
    }, token_auth: "my_secret_token")
    client = ElastomerClient::Client.new(**client_params)

    refute_match(/my_user/, client.inspect)
    refute_match(/my_secret_password/, client.inspect)
    refute_match(/my_secret_token/, client.inspect)
    assert_match(/@basic_auth=\[FILTERED\]/, client.inspect)
    assert_match(/@token_auth=\[FILTERED\]/, client.inspect)
  end

  describe "authorization" do
    it "can use basic authentication" do
      client_params = $client_params.merge(basic_auth: {
        username: "my_user",
        password: "my_secret_password"
      })
      client = ElastomerClient::Client.new(**client_params)

      connection = Faraday::Connection.new
      basic_auth_spy = Spy.on(connection, :basic_auth).and_return(nil)

      Faraday.stub(:new, $client_params[:url], connection) do
        client.ping
      end

      assert basic_auth_spy.has_been_called_with?("my_user", "my_secret_password")
    end

    it "ignores basic authentication if password is missing" do
      client_params = $client_params.merge(basic_auth: {
        username: "my_user"
      })
      client = ElastomerClient::Client.new(**client_params)

      connection = Faraday::Connection.new
      basic_auth_spy = Spy.on(connection, :basic_auth).and_return(nil)

      Faraday.stub(:new, $client_params[:url], connection) do
        client.ping
      end

      refute_predicate basic_auth_spy, :has_been_called?
    end

    it "ignores basic authentication if username is missing" do
      client_params = $client_params.merge(basic_auth: {
        password: "my_secret_password"
      })
      client = ElastomerClient::Client.new(**client_params)

      connection = Faraday::Connection.new
      basic_auth_spy = Spy.on(connection, :basic_auth).and_return(nil)

      Faraday.stub(:new, $client_params[:url], connection) do
        client.ping
      end

      refute_predicate basic_auth_spy, :has_been_called?
    end

    it "can use token authentication" do
      client_params = $client_params.merge(token_auth: "my_secret_token")
      client = ElastomerClient::Client.new(**client_params)

      connection = Faraday::Connection.new
      token_auth_spy = Spy.on(connection, :token_auth).and_return(nil)

      Faraday.stub(:new, $client_params[:url], connection) do
        client.ping
      end

      assert token_auth_spy.has_been_called_with?("my_secret_token")
    end

    it "prefers token authentication over basic" do
      client_params = $client_params.merge(basic_auth: {
        username: "my_user",
        password: "my_secret_password"
      }, token_auth: "my_secret_token")
      client = ElastomerClient::Client.new(**client_params)

      connection = Faraday::Connection.new
      basic_auth_spy = Spy.on(connection, :basic_auth).and_return(nil)
      token_auth_spy = Spy.on(connection, :token_auth).and_return(nil)

      Faraday.stub(:new, $client_params[:url], connection) do
        client.ping
      end

      refute_predicate basic_auth_spy, :has_been_called?
      assert token_auth_spy.has_been_called_with?("my_secret_token")
    end
  end

  describe "when extracting and converting :body params" do
    it "deletes the :body from the params (or it gets the hose)" do
      params = { body: nil, q: "what what?" }
      body = $client.extract_body params

      assert_nil body
      assert_equal({q: "what what?"}, params)
    end

    it "leaves String values unchanged" do
      body = $client.extract_body body: '{"query":{"match_all":{}}}'

      assert_equal '{"query":{"match_all":{}}}', body

      body = $client.extract_body body: "not a JSON string, but who cares!"

      assert_equal "not a JSON string, but who cares!", body
    end

    it "joins Array values" do
      body = $client.extract_body body: %w[foo bar baz]

      assert_equal "foo\nbar\nbaz\n", body

      body = $client.extract_body body: [
        "the first entry",
        "the second entry",
        nil
      ]

      assert_equal "the first entry\nthe second entry\n", body
    end

    it "converts values to JSON" do
      body = $client.extract_body body: true

      assert_equal "true", body

      body = $client.extract_body body: {query: {match_all: {}}}

      assert_equal '{"query":{"match_all":{}}}', body
    end

    it "returns frozen strings" do
      body = $client.extract_body body: '{"query":{"match_all":{}}}'

      assert_equal '{"query":{"match_all":{}}}', body
      assert_predicate body, :frozen?, "the body string should be frozen"

      body = $client.extract_body body: %w[foo bar baz]

      assert_equal "foo\nbar\nbaz\n", body
      assert_predicate body, :frozen?, "Array body strings should be frozen"

      body = $client.extract_body body: {query: {match_all: {}}}

      assert_equal '{"query":{"match_all":{}}}', body
      assert_predicate body, :frozen?, "JSON encoded body strings should be frozen"
    end
  end

  describe "when validating parameters" do
    it "rejects nil values" do
      assert_raises(ArgumentError) { $client.assert_param_presence nil }
    end

    it "rejects empty strings" do
      assert_raises(ArgumentError) { $client.assert_param_presence "" }
      assert_raises(ArgumentError) { $client.assert_param_presence " " }
      assert_raises(ArgumentError) { $client.assert_param_presence " \t \r \n " }
    end

    it "rejects empty strings and nil values found in arrays" do
      assert_raises(ArgumentError) { $client.assert_param_presence ["foo", nil, "bar"] }
      assert_raises(ArgumentError) { $client.assert_param_presence ["baz", " \t \r \n "] }
    end

    it "strips whitespace from strings" do
      assert_equal "foo", $client.assert_param_presence("  foo  \t")
    end

    it "joins array values into a string" do
      assert_equal "foo,bar", $client.assert_param_presence(%w[foo bar])
    end

    it "flattens arrays" do
      assert_equal "foo,bar,baz,buz", $client.assert_param_presence(["  foo  \t", %w[bar baz buz]])
    end

    it "allows strings" do
      assert_equal "foo", $client.assert_param_presence("foo")
    end

    it "converts numbers and symbols to strings" do
      assert_equal "foo", $client.assert_param_presence(:foo)
      assert_equal "9", $client.assert_param_presence(9)
    end
  end

  describe "top level actions" do
    it "pings the cluster" do
      assert $client.ping
      assert_predicate $client, :available?
    end

    it "gets cluster info" do
      h = $client.info

      assert h.key?("name"), "expected cluster name to be returned"
      assert h.key?("version"), "expected cluster version information to be returned"
      assert h["version"].key?("number"), "expected cluster version number to be returned"
    end

    it "gets cluster version" do
      assert_match(/[\d\.]+/, $client.version)
    end

    it "does not make an HTTP request for version if it is provided at create time" do
      request = stub_request(:get, "#{$client.url}/")

      client = ElastomerClient::Client.new(**$client_params.merge(es_version: "5.6.6"))

      assert_equal "5.6.6", client.version

      assert_not_requested request
    end

    it "gets semantic version" do
      version_string = $client.version

      assert_equal Semantic::Version.new(version_string), $client.semantic_version
    end
  end

  describe "retry logic" do
    it "defaults to no retries" do
      stub_request(:get, $client.url+"/_cat/indices").
        to_timeout.then.
        to_return({
          headers: {"Content-Type" => "text/plain; charset=UTF-8"},
          body: "green open test-index 1 0 0 0 159b 159b"
        })

      assert_raises(ElastomerClient::Client::ConnectionFailed) {
        $client.get("/_cat/indices")
      }
    end

    it "adding retry logic retries up to 2 times" do
      retry_count = 0

      retry_options = {
        max: 2,
        interval: 0.05,
        methods: [:get],
        exceptions: Faraday::Request::Retry::DEFAULT_EXCEPTIONS + [Faraday::ConnectionFailed],
        retry_block: proc { |env, options, retries, exc| retry_count += 1 }
      }
      retry_client = ElastomerClient::Client.new(port: 9205) do |connection|
        connection.request :retry, retry_options
      end

      stub_request(:get, retry_client.url + "/").
        to_timeout.then.
        to_timeout.then.
        to_return({body: %q/{"acknowledged": true}/})

      response = retry_client.get("/")

      assert_equal 2, retry_count
      assert_equal({"acknowledged" => true}, response.body)
    end
  end

  describe "duplicating a client connection" do
    it "is configured the same" do
      client = $client.dup

      refute_same $client, client

      assert_equal $client.host, client.host
      assert_equal $client.port, client.port
      assert_equal $client.url, client.url
      assert_equal $client.read_timeout, client.read_timeout
      assert_equal $client.open_timeout, client.open_timeout
      assert_equal $client.max_request_size, client.max_request_size
    end

    it "has a unique connection" do
      client = $client.dup

      refute_same $client.connection, client.connection
    end
  end

  describe "OpaqueIDError conditionals" do
    it "does not throw OpaqueIdError for mocked response with empty opaque id" do
      opts = $client_params.merge \
        opaque_id: true
      client = ElastomerClient::Client.new(**opts) do |connection|
        connection.request(:mock_response) { |env| env.body = "{}" }
      end

      response = client.get("/")

      assert_equal "yes", response.headers["Fake"]
    end

    it "throws OpaqueIdError on mismatched ID" do
      client_params = $client_params.merge \
        opaque_id: true
      client = ElastomerClient::Client.new(**client_params)

      test_url = "#{client.url}/"
      stub_request(:get, test_url).and_return(status: 200, headers: { "Content-Type" => "application/json", "X-Opaque-Id" => "foo" })

      assert_raises(ElastomerClient::Client::OpaqueIdError) { client.request :get, test_url, {} }
    end

    it "throws OpaqueIdError on empty string ID" do
      client_params = $client_params.merge \
        opaque_id: true
      client = ElastomerClient::Client.new(**client_params)

      test_url = "#{client.url}/"
      stub_request(:get, test_url).and_return(status: 200, headers: { "Content-Type" => "application/json", "X-Opaque-Id" => "" })

      assert_raises(ElastomerClient::Client::OpaqueIdError) { client.request :get, test_url, {} }
    end

    it "throws ServerError and not OpaqueIdError on 5xx response and nil ID" do
      client_params = $client_params.merge \
        opaque_id: true
      client = ElastomerClient::Client.new(**client_params)

      test_url = "#{client.url}/"
      stub_request(:get, test_url).and_return(status: 503, headers: { "Content-Type" => "application/json" })

      assert_raises(ElastomerClient::Client::ServerError) { client.request :get, test_url, {} }
    end
  end
end

```

# test/client/bulk_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"
require "json"

describe ElastomerClient::Client::Bulk do

  before do
    @name  = "elastomer-bulk-test"
    @index = $client.index(@name)

    unless @index.exists?
      @index.create \
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" }
          }
        })

      wait_for_index(@name)
    end
  end

  after do
    @index.delete if @index.exists?
  end

  it "performs bulk index actions" do
    body = [
      {index: document_wrapper("book", {_id: "1", _index: "elastomer-bulk-test"})}.to_json,
      '{"author":"Author 1", "title":"Book 1"}',
      {index: document_wrapper("book", {_id: "2", _index: "elastomer-bulk-test"})}.to_json,
      '{"author":"Author 2", "title":"Book 2"}',
      nil
    ]
    body = body.join "\n"
    h = $client.bulk body

    assert_bulk_index(h["items"][0])
    assert_bulk_index(h["items"][1])

    @index.refresh

    h = @index.docs("book").get id: 1

    assert_equal "Author 1", h["_source"]["author"]

    h = @index.docs("book").get id: 2

    assert_equal "Author 2", h["_source"]["author"]


    body = [
      {index: document_wrapper("book", {_id: "3"})}.to_json,
      '{"author":"Author 3", "title":"Book 3"}',
      {delete: document_wrapper("book", {_id: "1"})}.to_json,
      nil
    ]
    body = body.join "\n"
    h = $client.bulk body, index: @name

    assert_bulk_index h["items"].first, "expected to index a book"
    assert_bulk_delete h["items"].last, "expected to delete a book"

    @index.refresh

    h = @index.docs("book").get id: 1

    refute h["exists"], "was not successfully deleted"

    h = @index.docs("book").get id: 3

    assert_equal "Author 3", h["_source"]["author"]
  end

  it "supports a nice block syntax" do
    h = @index.bulk do |b|
      b.index({ author: "Author 1", title: "Book 1" }, { _id: 1, _type: "book" })
      b.index({ author: "Author 2", title: "Book 2" }, { _id: nil, _type: "book" })
    end
    items = h["items"]

    assert_kind_of Integer, h["took"]

    assert_equal 2, h["items"].length

    assert_bulk_index h["items"].first
    assert_bulk_index h["items"].last
    book_id = items.last["index"]["_id"]

    assert_match %r/^\S{20,22}$/, book_id

    @index.refresh

    h = @index.docs("book").get id: 1

    assert_equal "Author 1", h["_source"]["author"]

    h = @index.docs("book").get id: book_id

    assert_equal "Author 2", h["_source"]["author"]

    h = @index.bulk do |b|
      b.index({ author: "Author 3", title: "Book 3" }, _id: "", _type: "book")
      b.delete ({_id: book_id, _type: "book"})
    end
    items = h["items"]

    assert_equal 2, h["items"].length

    assert_bulk_index h["items"].first, "expected to create a book"
    assert_bulk_delete h["items"].last, "expected to delete a book"

    book_id2 = items.first["index"]["_id"]

    assert_match %r/^\S{20,22}$/, book_id2

    @index.refresh

    h = @index.docs("book").get id: book_id

    refute h["exists"], "was not successfully deleted"

    h = @index.docs("book").get id: book_id2

    assert_equal "Author 3", h["_source"]["author"]
  end

  it "allows documents to be JSON strings" do
    h = @index.bulk do |b|
      b.index  '{"author":"Author 1", "title":"Book 1"}', {_id: 1, _type: "book"}
      b.create '{"author":"Author 2", "title":"Book 2"}', {_id: 2, _type: "book"}
    end

    assert_kind_of Integer, h["took"]

    assert_bulk_index h["items"].first
    assert_bulk_create h["items"].last

    @index.refresh

    h = @index.docs("book").get id: 1

    assert_equal "Author 1", h["_source"]["author"]

    h = @index.docs("book").get id: 2

    assert_equal "Author 2", h["_source"]["author"]

    h = @index.bulk do |b|
      b.index '{"author":"Author 3", "title":"Book 3"}', {_id: 3, _type: "book"}
      b.delete ({_id: 1, _type: "book"})
    end

    assert_bulk_index h["items"].first, "expected to index a book"
    assert_bulk_delete h["items"].last, "expected to delete a book"

    @index.refresh

    h = @index.docs("book").get id: 1

    refute h["exists"], "was not successfully deleted"

    h = @index.docs("book").get id: 3

    assert_equal "Author 3", h["_source"]["author"]
  end

  it "executes a bulk API call when a request size is reached" do
    ary = []
    # since ES8 does not include the mapping type in the document, it has less characters per request
    # add characters to the document to get 100 characters per request
    book_title = $client.version_support.es_version_8_plus? ? "A"*52 : "A"*34
    ary << @index.bulk(request_size: 300) do |b|
      2.times { |num|
        document = { author: "Author 1", title: book_title}
        ary << b.index(document, { _id: num, _type: "book" })
      }
      ary.compact!

      assert_equal 0, ary.length

      7.times { |num|
        document = { author: "Author 1", title: book_title }
        ary << b.index(document, { _id: num+2,  _type: "book" })
      }
      ary.compact!

      assert_equal 4, ary.length

      document = {author: "Author 1", title: book_title}
      ary << b.index(document, {_id: 10,  _type: "book"})
    end
    ary.compact!

    assert_equal 5, ary.length
    ary.each { |a| a["items"].each { |b| assert_bulk_index(b) } }

    @index.refresh
    h = @index.docs.search q: "*:*", size: 0

    if $client.version_support.es_version_8_plus?
      assert_equal 10, h["hits"]["total"]["value"]
    else
      assert_equal 10, h["hits"]["total"]
    end
  end

  it "executes a bulk API call when an action count is reached" do
    ary = []
    ary << @index.bulk(action_count: 3) do |b|
      2.times { |num|
        document = {author: "Author 1", title: "This is book number #{num}"}
        ary << b.index(document, {_id: num,  _type: "book"})
      }
      ary.compact!

      assert_equal 0, ary.length

      7.times { |num|
        document = {author: "Author 1", title: "This is book number #{num+2}"}
        ary << b.index(document, {_id: num+2, _type: "book"})
      }
      ary.compact!

      assert_equal 2, ary.length

      document = {author: "Author 1", title: "This is book number 10"}
      ary << b.index(document, {_id: 10,  _type: "book"})
    end
    ary.compact!

    assert_equal 4, ary.length
    ary.each { |a| a["items"].each { |b| assert_bulk_index(b) } }

    @index.refresh
    h = @index.docs.search q: "*:*", size: 0

    if $client.version_support.es_version_8_plus?
      assert_equal 10, h["hits"]["total"]["value"]
    else
      assert_equal 10, h["hits"]["total"]
    end
  end

  it "rejects documents that exceed the maximum request size" do
    client = ElastomerClient::Client.new(**$client_params.merge(max_request_size: 300))
    index  = client.index(@name)

    ary = []
    book_title = $client.version_support.es_version_8_plus? ? "A"*52 : "A"*34
    ary << index.bulk(request_size: 300) do |b|
      2.times { |num|
        document = {author: "Author 1", title: book_title}
        ary << b.index(document, document_wrapper("book", { _id: num }))
      }
      ary.compact!

      assert_equal 0, ary.length

      document = { author: "Author 1", message: "A"*290 }
      assert_raises(ElastomerClient::Client::RequestSizeError) { b.index(document, document_wrapper("book", { _id: 342 })) }
    end
    ary.compact!

    assert_equal 1, ary.length
    ary.each { |a| a["items"].each { |b| assert_bulk_index(b) } }

    index.refresh
    h = index.docs.search q: "*:*", size: 0

    if $client.version_support.es_version_8_plus?
      assert_equal 2, h["hits"]["total"]["value"]
    else
      assert_equal 2, h["hits"]["total"]
    end
  end

  it "uses :id from parameters and supports symbol and string parameters" do
    response = @index.bulk do |b|
      document1 = { author: "Author 1", title: "Book 1" }
      b.index document1, { id: "foo", type: "book" }

      document2 = { author: "Author 2", title: "Book 2" }
      b.index document2, { "id" => "bar", "type" => "book" }
    end

    assert_kind_of Integer, response["took"]

    items = response["items"]

    assert_bulk_index(items[0])

    assert_equal "foo", items[0]["index"]["_id"]
    assert_equal "Book 1", @index.docs("book").get(id: "foo")["_source"]["title"]

    assert_equal "bar", items[1]["index"]["_id"]
    assert_equal "Book 2", @index.docs("book").get(id: "bar")["_source"]["title"]
  end

  it "empty symbol and string parameters don't set id" do
    response = @index.bulk do |b|
      document1 = { author: "Author 1", title: "Book 1" }
      b.index document1,  { id: "", type: "book" }

      document2 = { author: "Author 2", title: "Book 2" }
      b.index document2, { "id" => "", "type" => "book" }
    end

    assert_kind_of Integer, response["took"]

    items = response["items"]

    assert_bulk_index(items[0])

    # ES will generate ids for these documents
    id1 = items[0]["index"]["_id"]
    id2 = items[1]["index"]["_id"]

    assert_equal "Book 1", @index.docs("book").get(id: id1)["_source"]["title"]
    assert_equal "Book 2", @index.docs("book").get(id: id2)["_source"]["title"]
  end

  it "supports the routing parameter on index actions" do
    document = { title: "Book 1" }

    response = @index.bulk do |b|
      b.index document, { routing: "custom", _id: 1,  _type: "book" }
    end

    items = response["items"]

    assert_kind_of Integer, response["took"]
    assert_bulk_index(items[0])
    assert_equal "custom", @index.docs("book").get(id: 1)["_routing"]
  end

  it "supports the routing parameter within params in ES5 and ES8" do
    document = { title: "Book 1" }

    params = { _id: 1, _type: "book" }
    if $client.version_support.es_version_8_plus?
      params[:routing] = "custom"
    else
      params[:_routing] = "custom"
    end

    response = @index.bulk do |b|
      b.index document, params
    end

    items = response["items"]

    assert_kind_of Integer, response["took"]
    assert_bulk_index(items[0])
    assert_equal "custom", @index.docs("book").get(id: 1)["_routing"]
  end

  it "streams bulk responses" do
    ops = [
      [:index, { title: "Book 1" }, document_wrapper("book", { _id: 1, _index: @index.name })],
      [:index, { title: "Book 2" }, document_wrapper("book", { _id: 2, _index: @index.name })],
      [:index, { title: "Book 3" }, document_wrapper("book", { _id: 3, _index: @index.name })],
    ]
    responses = $client.bulk_stream_responses(ops, { action_count: 2 }).to_a

    assert_equal(2, responses.length)
    assert_bulk_index(responses[0]["items"][0])
    assert_bulk_index(responses[0]["items"][1])
    assert_bulk_index(responses[1]["items"][0])
  end

  it "streams bulk items" do
    ops = [
      [:index, { title: "Book 1" }, document_wrapper("book", { _id: 1, _index: @index.name })],
      [:index, { title: "Book 2" }, document_wrapper("book", { _id: 2, _index: @index.name })],
      [:index, { title: "Book 3" }, document_wrapper("book", { _id: 3, _index: @index.name })],
    ]
    items = []
    $client.bulk_stream_items(ops, { action_count: 2 }) { |item| items << item }

    assert_equal(3, items.length)
    assert_bulk_index(items[0])
    assert_bulk_index(items[1])
    assert_bulk_index(items[2])
  end
end

```

# test/client/cluster_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Cluster do

  before do
    @name = "elastomer-cluster-test"
    @index = $client.index @name
    @index.delete if @index.exists?
    @cluster = $client.cluster
  end

  after do
    @index.delete if @index.exists?
  end

  it "gets the cluster health" do
    h = @cluster.health

    assert h.key?("cluster_name"), "the cluster name is returned"
    assert h.key?("status"), "the cluster status is returned"
  end

  it "gets the cluster state" do
    h = @cluster.state

    assert h.key?("cluster_name"), "the cluster name is returned"
    assert h.key?("master_node"), "the master node is returned"
    assert_instance_of Hash, h["nodes"], "the node list is returned"
    assert_instance_of Hash, h["metadata"], "the metadata are returned"
  end

  it "filters cluster state by metrics" do
    h = @cluster.state(metrics: "nodes")

    refute h.key("metadata"), "expected only nodes state"
    h = @cluster.state(metrics: "metadata")

    refute h.key("nodes"), "expected only metadata state"
  end

  it "filters cluster state by indices" do
    @index.create(default_index_settings) unless @index.exists?
    h = @cluster.state(metrics: "metadata", indices: @name)

    assert_equal [@name], h["metadata"]["indices"].keys
  end

  it "gets the cluster settings" do
    h = @cluster.get_settings

    assert_instance_of Hash, h["persistent"], "the persistent settings are returned"
    assert_instance_of Hash, h["transient"], "the transient settings are returned"
  end

  it "gets the cluster settings with .settings" do
    h = @cluster.settings

    assert_instance_of Hash, h["persistent"], "the persistent settings are returned"
    assert_instance_of Hash, h["transient"], "the transient settings are returned"
  end

  it "updates the cluster settings" do
    @cluster.update_settings transient: { "indices.recovery.max_bytes_per_sec" => "30mb" }
    h = @cluster.settings

    value = h["transient"]["indices"]["recovery"]["max_bytes_per_sec"]

    assert_equal "30mb", value

    @cluster.update_settings transient: { "indices.recovery.max_bytes_per_sec" => "60mb" }
    h = @cluster.settings

    value = h["transient"]["indices"]["recovery"]["max_bytes_per_sec"]

    assert_equal "60mb", value
  end

  it "returns cluster stats" do
    h = @cluster.stats
    expected = $client.version_support.es_version_8_plus? ? %w[cluster_name cluster_uuid indices nodes snapshots status timestamp] : %w[cluster_name indices nodes status timestamp]
    expected.unshift("_nodes")

    assert_equal expected, h.keys.sort
  end

  it "returns a list of pending tasks" do
    h = @cluster.pending_tasks

    assert_equal %w[tasks], h.keys.sort
    assert_kind_of Array, h["tasks"], "the tasks lists is always an Array even if empty"
  end

  it "returns the list of indices in the cluster" do
    @index.create(default_index_settings) unless @index.exists?
    indices = @cluster.indices

    refute_empty indices, "expected to see an index"
  end

  it "returns the list of nodes in the cluster" do
    nodes = @cluster.nodes

    refute_empty nodes, "we have to have some nodes"
  end

  describe "when working with aliases" do
    before do
      @name = "elastomer-cluster-test"
      @index = $client.index @name
      @index.create(default_index_settings) unless @index.exists?
      wait_for_index(@name)
    end

    after do
      @index.delete if @index.exists?
    end

    it "adds and gets an alias" do
      hash = @cluster.get_aliases

      assert_empty hash[@name]["aliases"]

      @cluster.update_aliases \
        add: {index: @name, alias: "elastomer-test-unikitty"}

      hash = @cluster.get_aliases

      assert_equal ["elastomer-test-unikitty"], hash[@name]["aliases"].keys
    end

    it "adds and gets an alias with .aliases" do
      hash = @cluster.aliases

      assert_empty hash[@name]["aliases"]

      @cluster.update_aliases \
        add: {index: @name, alias: "elastomer-test-unikitty"}

      hash = @cluster.aliases

      assert_equal ["elastomer-test-unikitty"], hash[@name]["aliases"].keys
    end

    it "removes an alias" do
      @cluster.update_aliases \
        add: {index: @name, alias: "elastomer-test-unikitty"}

      hash = @cluster.get_aliases

      assert_equal ["elastomer-test-unikitty"], hash[@name]["aliases"].keys

      @cluster.update_aliases([
        {add:    {index: @name, alias: "elastomer-test-SpongeBob-SquarePants"}},
        {remove: {index: @name, alias: "elastomer-test-unikitty"}}
      ])

      hash = @cluster.get_aliases

      assert_equal ["elastomer-test-SpongeBob-SquarePants"], hash[@name]["aliases"].keys
    end

    it "accepts the full aliases actions hash" do
      @cluster.update_aliases actions: [
        {add: {index: @name, alias: "elastomer-test-He-Man"}},
        {add: {index: @name, alias: "elastomer-test-Skeletor"}}
      ]

      hash = @cluster.get_aliases(index: @name)

      assert_equal %w[elastomer-test-He-Man elastomer-test-Skeletor], hash[@name]["aliases"].keys.sort
    end
  end

end

```

# test/client/docs_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Docs do

  before do
    @name  = "elastomer-docs-test"
    @index = $client.index(@name)

    unless @index.exists?
      @index.create \
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "text", analyzer: "standard", term_vector: "with_positions_offsets" },
            author: { type: "keyword" }
          }
        }, true)

      # COMPATIBILITY
      if !$client.version_support.es_version_8_plus?
        @index.update_mapping("percolator", { properties: { query: { type: "percolator"}}})
      end

      wait_for_index(@name)
    end

    @docs = @index.docs
  end

  after do
    @index.delete if @index.exists?
  end

  it "raises error when writing same document twice" do
    document = ({
      _id: "documentid",
      _type: "book",
      _op_type: "create",
      title: "Book by Author1",
      author: "Author1"
    })
    h = @docs.index document.dup

    assert_created h

    assert_raises(ElastomerClient::Client::DocumentAlreadyExistsError) do
      @docs.index document.dup
    end
  end

  it "autogenerates IDs for documents" do
    h = @docs.index(
      {
        _id: nil,
        title: "Book1 by author 1",
        author: "Author1",
        _type: "book"
      })

    assert_created h
    assert_match %r/^\S{20,22}$/, h["_id"]

    h = @docs.index(
      {
        _id: nil,
        title: "Book2 by author 2",
        author: "Author2",
        _type: "book"
      })

    assert_created h
    assert_match %r/^\S{20,22}$/, h["_id"]
  end

  it "uses the provided document ID" do
    h = @docs.index (
      {
        _id: 42,
        _type: "book",
        title: "Book1 by author 1",
        author: "Author1"
      })

    assert_created h
    assert_equal "42", h["_id"]
  end

  it "accepts JSON encoded document strings" do
    h = @docs.index \
      '{"author":"Author1", "title":"Book1 by author 1"}',
      id: 42,
      type: "book"

    assert_created h
    assert_equal "42", h["_id"]
  end

  describe "indexing directive fields" do
    before do
      # Since we set dynamic: strict, adding the above doc to the index throws an error, so update the index to allow dynamic mapping
      if !$client.version_support.es_version_8_plus?
        @index.update_mapping "book", { book: { dynamic: "true" } }
      end
    end

    after do
      # Since we set dynamic: strict, adding the above doc to the index throws an error, so update the index to allow dynamic mapping
      if !$client.version_support.es_version_8_plus?
        @index.update_mapping "book", { book: { dynamic: "strict" } }
      end
    end

    it "indexes fields that are not recognized as indexing directives" do
      doc = ({
        _id: "12",
        _type: "book",
        title: "Book1",
        author: "Author1",
        _unknown_1: "unknown attribute 1",
        "_unknown_2": "unknown attribute 2"
      })

      h = @docs.index(doc)

      assert_created h
      assert_equal "12", h["_id"]

      indexed_doc = $client.version_support.es_version_8_plus? ? @docs.get(id: "12") : @docs.get(type: "book", id: "12")
      expected = {
        "title" => "Book1",
        "author" => "Author1",
        "_unknown_1" => "unknown attribute 1",
        "_unknown_2" => "unknown attribute 2"
      }

      assert_equal expected, indexed_doc["_source"]
    end

    it "extracts indexing directives from the document" do
      doc = {
        _id: "12",
        _type: "book",
        _routing: "author",
        title: "Book1",
        author: "Author1"
      }

      h = @docs.index(doc)

      assert_created h
      assert_equal "12", h["_id"]

      # Special keys are removed from the document hash
      refute doc.key?(:_id)
      refute doc.key?("_type")
      refute doc.key?(:_routing)

      indexed_doc = $client.version_support.es_version_8_plus? ? @docs.get(id: "12") : @docs.get(type: "book", id: "12")
      expected = {
        "title" => "Book1",
        "author" => "Author1"
      }

      assert_equal expected, indexed_doc["_source"]
    end

    it "raises an exception when a known indexing directive from an unsupported version is used" do
      # Symbol keys
      doc = ({
        _id: "12",
        _type: "book",
        title: "Book1",
       _consistency: "all"
      })

      assert_raises(ElastomerClient::Client::IllegalArgument) do
        @docs.index(doc)
      end

      # String keys
      doc = ({
        "_id" => "12",
        "_type" => "book",
        "title" => "Book1",
        "_consistency" => "all"
      })

      assert_raises(ElastomerClient::Client::IllegalArgument) do
        @docs.index(doc)
      end
    end
  end

  it "gets documents from the search index" do
    h = $client.version_support.es_version_8_plus? ? @docs.get(id: "1") : @docs.get(id: "1", type: "book")

    refute_found h

    populate!

    h = $client.version_support.es_version_8_plus? ? @docs.get(id: "1") : @docs.get(id: "1", type: "book")

    assert_found h
    assert_equal "Author1", h["_source"]["author"]
  end

  it "checks if documents exist in the search index" do
    refute $client.version_support.es_version_8_plus? ? @docs.exists?(id: "1") : @docs.exists?(id: "1", type: "book")
    populate!

    assert $client.version_support.es_version_8_plus? ? @docs.exists?(id: "1") : @docs.exists?(id: "1", type: "book")
  end

  it "checks if documents exist in the search index with .exist?" do
    refute $client.version_support.es_version_8_plus? ? @docs.exist?(id: "1") : @docs.exist?(id: "1", type: "book")
    populate!

    assert $client.version_support.es_version_8_plus? ? @docs.exist?(id: "1") : @docs.exist?(id: "1", type: "book")
  end

  it "gets multiple documents from the search index" do
    populate!

    h = @docs.multi_get docs: [
      document_wrapper("book", { _id: 1 }),
      document_wrapper("book", { _id: 2 })
    ]
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author1 Author2], authors

    h = $client.version_support.es_version_8_plus? ? @docs.multi_get({ids: [2, 1]}) : @docs.multi_get({ids: [2, 1]}, type: "book")
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author2 Author1], authors

    h = @index.docs("book").multi_get ids: [1, 2, 3, 4]

    assert_found h["docs"][0]
    assert_found h["docs"][1]
    refute_found h["docs"][2]
    refute_found h["docs"][3]
  end

  it "gets multiple documents from the search index with .mget" do
    populate!

    h = @docs.mget docs: [
      document_wrapper("book", { _id: 1 }),
      document_wrapper("book", { _id: 2 })
    ]
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author1 Author2], authors

    h = @docs.mget({ids: [2, 1]})
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author2 Author1], authors

    h = @index.docs("book").mget ids: [1, 2, 3, 4]

    assert_found h["docs"][0]
    assert_found h["docs"][1]
    refute_found h["docs"][2]
    refute_found h["docs"][3]
  end

  it "deletes documents from the search index" do
    populate!
    @docs = @index.docs("book")

    h = @docs.multi_get ids: [1, 2]
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author1 Author2], authors

    h = @docs.delete id: 1

    if $client.version_support.es_version_8_plus?
      assert_equal "deleted", h["result"], "expected document to be found"
    else
      assert h["found"], "expected document to be found"
    end

    h = @docs.multi_get ids: [1, 2]

    refute_found h["docs"][0]
    assert_found h["docs"][1]

    assert_raises(ArgumentError) { @docs.delete id: nil }
    assert_raises(ArgumentError) { @docs.delete id: "" }
    assert_raises(ArgumentError) { @docs.delete id: "\t" }
  end

  it "does not care if you delete a document that is not there" do
    @docs = @index.docs("book")
    h = @docs.delete id: 42

    if $client.version_support.es_version_8_plus?
      refute_equal "deleted", h["result"], "expected document to not be found"
    else
      refute h["found"], "expected document to not be found"
    end
  end

  it "deletes documents by query" do
    populate!
    @docs = @index.docs("book")

    h = @docs.multi_get ids: [1, 2]
    authors = h["docs"].map { |d| d["_source"]["author"] }

    assert_equal %w[Author1 Author2], authors

    h = @docs.delete_by_query(q: "author:Author2")

    assert_equal(1, h["deleted"])

    @index.refresh
    h = @docs.multi_get ids: [1, 2]

    assert_found h["docs"][0]
    refute_found h["docs"][1]

    h = @docs.delete_by_query(
      query: {
        bool: {
          filter: {term: {author: "Author1"}}
        }
      }
    )
    @index.refresh
    h = @docs.multi_get ids: [1, 2]

    refute_found h["docs"][0]
    refute_found h["docs"][1]
  end

  it "updates documents by query" do
    populate!

    r = @docs.update_by_query(query: {
      bool: {
        filter: {term: {author: "Author1"}}
      }
    }, script: {
      source: "ctx._source.author = 'Author1 Updated'"
    })

    assert_equal 1, r["updated"]

    r = @docs.update_by_query({
      query: {
        bool: {
          filter: {term: {author: "Author2"}}
        }
      },
      script: {
        source: "ctx._source.author = 'Author2 Updated'"
      }
    }, conflicts: "proceed")

    assert_equal 1, r["updated"]

    @index.refresh

    h = @docs.multi_get ids: [1, 2]

    assert_equal "Author1 Updated", h["docs"][0]["_source"]["author"]
    assert_equal "Author2 Updated", h["docs"][1]["_source"]["author"]

  end

  it "searches for documents" do
    h = @docs.search q: "*:*"

    if $client.version_support.es_version_8_plus?
      assert_equal 0, h["hits"]["total"]["value"]
    else
      assert_equal 0, h["hits"]["total"]
    end

    populate!

    h = @docs.search q: "*:*"

    if $client.version_support.es_version_8_plus?
      assert_equal 2, h["hits"]["total"]["value"]
    else
      assert_equal 2, h["hits"]["total"]
    end

    if !$client.version_support.es_version_8_plus?
      h = @docs.search q: "*:*", type: "book"

      assert_equal 2, h["hits"]["total"]
    end

    h = @docs.search({
      query: {match_all: {}},
      post_filter: {term: {author: "Author1"}}
    })

    if $client.version_support.es_version_8_plus?
      assert_equal 1, h["hits"]["total"]["value"]
    else
      assert_equal 1, h["hits"]["total"]
    end

    hit = h["hits"]["hits"].first

    assert_equal "Book1 by author 1", hit["_source"]["title"]
  end

  it "supports the shards search API" do
    h = @docs.search_shards(params={})

    assert h.key?("nodes"), "response contains \"nodes\" information"
    assert h.key?("shards"), "response contains \"shards\" information"
    assert_kind_of Array, h["shards"], "\"shards\" is an array"
  end

  it "generates QueryParsingError exceptions on bad input when searching" do
    query = {query: {query_string: {query: "OR should fail"}}}
    assert_raises(ElastomerClient::Client::QueryParsingError) { @docs.search(query) }

    query = {query: {foo_is_not_valid: {}}}
    assert_raises(ElastomerClient::Client::QueryParsingError) { @docs.search(query) }
  end

  it "counts documents" do
    h = @docs.count q: "*:*"

    assert_equal 0, h["count"]

    populate!

    h = @docs.count q: "*:*"

    assert_equal 2, h["count"]

    if !$client.version_support.es_version_8_plus?
      h = @docs.count(q: "*:*", type: "book")

      assert_equal 2, h["count"]
    end

    h = @docs.count({
      query: {
        bool: {
          filter: {term: {author: "Author1"}}
        }
      }
    })

    assert_equal 1, h["count"]
  end

  it "explains scoring" do
    populate!

    h = $client.version_support.es_version_8_plus? ?
      @docs.explain({
        query: {
          match: {
            "author" => "Author1"
          }
        }
      }, id: 1)
      : @docs.explain({
        query: {
          match: {
            "author" => "Author1"
          }
        }
      }, id: 1, type: "book")

    assert h["matched"]

    h = $client.version_support.es_version_8_plus? ? @docs.explain(id: 2, q: "Author1") : @docs.explain(type: "book", id: 2, q: "Author1")

    refute h["matched"]
  end

  it "validates queries" do
    populate!

    h = @docs.validate q: "*:*"

    assert h["valid"]

    h = @docs.validate({
      query: {
        filtered: {
          query: {match_all: {}},
          filter: {term: {author: "Author2"}}
        }
      }
    })

    refute h["valid"]

    h = @docs.validate({
      query: {
        bool: {
          filter: {term: {author: "Author2"}}
        }
      }
    })

    assert h["valid"]
  end

  it "updates documents" do
    populate!

    h = $client.version_support.es_version_8_plus? ? @docs.get(id: "1") : @docs.get(id: "1", type: "book")

    assert_found h
    assert_equal "Author1", h["_source"]["author"]

    @docs.update(document_wrapper("book", {
      _id: "1",
      doc: {author: "Author1.1"}
    }))
    h = $client.version_support.es_version_8_plus? ? @docs.get(id: "1") : @docs.get(id: "1", type: "book")

    assert_found h
    assert_equal "Author1.1", h["_source"]["author"]

    if $client.version >= "0.90"
      @docs.update(document_wrapper("book", {
        _id: "42",
        doc: {
          author: "Author42",
          title: "Book42"
        },
        doc_as_upsert: true
      }))

      h = $client.version_support.es_version_8_plus? ? @docs.get(id: "42") : @docs.get(id: "42", type: "book")

      assert_found h
      assert_equal "Author42", h["_source"]["author"]
      assert_equal "Book42", h["_source"]["title"]
    end
  end

  it "supports bulk operations with the same parameters as docs" do
    response = @docs.bulk do |b|
      populate_with_params!(b)
    end

    assert_kind_of Integer, response["took"]

    response = $client.version_support.es_version_8_plus? ? @docs.get(id: 1) : @docs.get(id: 1, type: "book")

    assert_found response
    assert_equal "Author1", response["_source"]["author"]
  end

  it "provides access to term vector statistics" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.termvector(id: 1, fields: "title") : @docs.termvector(type: "book", id: 1, fields: "title")

    assert response["term_vectors"]["title"]
    assert response["term_vectors"]["title"]["field_statistics"]
    assert response["term_vectors"]["title"]["terms"]
    assert_equal %w[1 author book1 by], response["term_vectors"]["title"]["terms"].keys
  end

  it "provides access to term vector statistics with .termvectors" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.termvectors(id: 1, fields: "title") : @docs.termvectors(type: "book", id: 1, fields: "title")

    assert response["term_vectors"]["title"]
    assert response["term_vectors"]["title"]["field_statistics"]
    assert response["term_vectors"]["title"]["terms"]
    assert_equal %w[1 author book1 by], response["term_vectors"]["title"]["terms"].keys
  end

  it "provides access to term vector statistics with .term_vector" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.term_vector(id: 1, fields: "title") : @docs.term_vector(type: "book", id: 1, fields: "title")

    assert response["term_vectors"]["title"]
    assert response["term_vectors"]["title"]["field_statistics"]
    assert response["term_vectors"]["title"]["terms"]
    assert_equal %w[1 author book1 by], response["term_vectors"]["title"]["terms"].keys
  end

  it "provides access to term vector statistics with .term_vectors" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.term_vectors(id: 1, fields: "title") : @docs.term_vectors(type: "book", id: 1, fields: "title")

    assert response["term_vectors"]["title"]
    assert response["term_vectors"]["title"]["field_statistics"]
    assert response["term_vectors"]["title"]["terms"]
    assert_equal %w[1 author book1 by], response["term_vectors"]["title"]["terms"].keys
  end

  it "provides access to multi term vector statistics" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.multi_termvectors({ids: [1, 2]}, fields: "title", term_statistics: true) : @docs.multi_termvectors({ids: [1, 2]}, type: "book", fields: "title", term_statistics: true)
    docs = response["docs"]

    assert docs
    assert_equal(%w[1 2], docs.map { |h| h["_id"] }.sort)
  end

  it "provides access to multi term vector statistics with .multi_term_vectors" do
    populate!

    response = $client.version_support.es_version_8_plus? ? @docs.multi_term_vectors({ids: [1, 2]}, fields: "title", term_statistics: true) : @docs.multi_term_vectors({ids: [1, 2]}, type: "book", fields: "title", term_statistics: true)
    docs = response["docs"]

    assert docs
    assert_equal(%w[1 2], docs.map { |h| h["_id"] }.sort)
  end

  it "percolates a given document" do
    if $client.version_support.es_version_8_plus?
      skip "Percolate not supported in ES version #{$client.version}"
    end

    populate!

    percolator1 = @index.percolator "1"
    response = percolator1.create query: { match: { author: "Author1" } }

    assert response["created"], "Couldn't create the percolator query"
    percolator2 = @index.percolator "2"
    response = percolator2.create query: { match: { author: "Author2" } }

    assert response["created"], "Couldn't create the percolator query"
    @index.refresh

    response = @index.docs("book").percolate(doc: { author: "Author1" })

    assert_equal 1, response["matches"].length
    assert_equal "1", response["matches"][0]["_id"]
  end

  it "percolates an existing document" do
    if $client.version_support.es_version_8_plus?
      skip "Percolate not supported in ES version #{$client.version}"
    end

    populate!

    percolator1 = @index.percolator "1"
    response = percolator1.create query: { match: { author: "Author1" } }

    assert response["created"], "Couldn't create the percolator query"
    percolator2 = @index.percolator "2"
    response = percolator2.create query: { match: { author: "Author2" } }

    assert response["created"], "Couldn't create the percolator query"
    @index.refresh

    response = @index.docs("book").percolate(nil, id: "1")

    assert_equal 1, response["matches"].length
    assert_equal "1", response["matches"][0]["_id"]
  end

  it "counts the matches for percolating a given document" do
    if $client.version_support.es_version_8_plus?
      skip "Percolate not supported in ES version #{$client.version}"
    end

    populate!

    percolator1 = @index.percolator "1"
    response = percolator1.create query: { match: { author: "Author1" } }

    assert response["created"], "Couldn't create the percolator query"
    percolator2 = @index.percolator "2"
    response = percolator2.create query: { match: { author: "Author2" } }

    assert response["created"], "Couldn't create the percolator query"
    @index.refresh

    count = @index.docs("book").percolate_count doc: { author: "Author1" }

    assert_equal 1, count
  end

  it "counts the matches for percolating an existing document" do
    if $client.version_support.es_version_8_plus?
      skip "Percolate not supported in ES version #{$client.version}"
    end

    populate!

    percolator1 = @index.percolator "1"
    response = percolator1.create query: { match: { author: "Author1" } }

    assert response["created"], "Couldn't create the percolator query"
    percolator2 = @index.percolator "2"
    response = percolator2.create query: { match: { author: "Author2" } }

    assert response["created"], "Couldn't create the percolator query"
    @index.refresh

    count = @index.docs("book").percolate_count(nil, id: "1")

    assert_equal 1, count
  end

  it "performs multi percolate queries" do
    if $client.version_support.es_version_8_plus?
      skip "Multi percolate not supported in ES version #{$client.version}"
    end

    @index.percolator("1").create query: { match_all: { } }
    @index.percolator("2").create query: { match: { author: "Author1" } }
    @index.refresh

    h = @index.docs("book").multi_percolate do |m|
      m.percolate author: "Author1"
      m.percolate author: "Author2"
      m.count({}, { author: "Author2" })
    end

    response1, response2, response3 = h["responses"]

    assert_equal ["1", "2"], response1["matches"].map { |match| match["_id"] }.sort
    assert_equal ["1"], response2["matches"].map { |match| match["_id"] }.sort
    assert_equal 1, response3["total"]
  end

  # Create/index multiple documents.
  #
  # docs - An instance of ElastomerClient::Client::Docs or ElastomerClient::Client::Bulk. If
  #        nil uses the @docs instance variable.
  def populate!(docs = @docs)
    docs.index ({
        _id: 1,
        _type: "book",
        title: "Book1 by author 1",
        author: "Author1"
      })

    docs.index ({
        _id: 2,
        _type: "book",
        title: "Book2 by author 2",
        author: "Author2"
      })

    @index.refresh
  end

  def populate_with_params!(docs = @docs)
    docs.index({
        title: "Book1 by author 1",
        author: "Author1"
      }, { _id: 1, _type: "book" })

    docs.index({
        title: "Book2 by author 2",
        author: "Author2"
      }, { _id: 2, _type: "book" })

    @index.refresh
  end
  # rubocop:enable Metrics/MethodLength

end

```

# test/client/errors_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Error do

  it "is instantiated with a simple message" do
    err = ElastomerClient::Client::Error.new "something went wrong"

    assert_equal "something went wrong", err.message
  end

  it "is instantiated from an HTTP response" do
    response = Faraday::Response.new(body: "UTF8Error invalid middle-byte")
    err = ElastomerClient::Client::Error.new(response)

    assert_equal "UTF8Error invalid middle-byte", err.message

    response = Faraday::Response.new(body: {"error" => "IndexMissingException"})
    err = ElastomerClient::Client::Error.new(response)

    assert_equal "IndexMissingException", err.message
    assert_equal "IndexMissingException", err.error

    body = {
      "error" => {
        "index"         => "non-existent-index",
        "reason"        => "no such index",
        "resource.id"   => "non-existent-index",
        "resource.type" => "index_or_alias",
        "root_cause"=> [{
          "index"         => "non-existent-index",
          "reason"        => "no such index",
          "resource.id"   => "non-existent-index",
          "resource.type" => "index_or_alias",
          "type"          => "index_not_found_exception"
        }],
       "type" => "index_not_found_exception"
      },
     "status" => 404
    }
    response = Faraday::Response.new(body:)
    err = ElastomerClient::Client::Error.new(response)

    assert_equal body["error"].to_s, err.message
    assert_equal body["error"], err.error
  end

  it "is instantiated from another exception" do
    err = Faraday::ConnectionFailed.new "could not connect to host"
    err.set_backtrace %w[one two three four]

    err = ElastomerClient::Client::Error.new(err, "POST", "/index/doc")

    assert_equal "could not connect to host :: POST /index/doc", err.message
    assert_equal %w[one two three four], err.backtrace
  end

  it "is fatal by default" do
    assert ElastomerClient::Client::Error.fatal, "client errors are fatal by default"

    error = ElastomerClient::Client::Error.new "oops!"

    refute_predicate error, :retry?, "client errors are not retryable by default"
  end

  it "supports .fatal? alias" do
    assert_predicate ElastomerClient::Client::Error, :fatal?, "client errors support .fatal?"
  end

  it "has some fatal subclasses" do
    assert ElastomerClient::Client::ResourceNotFound.fatal, "Resource not found is fatal"
    assert ElastomerClient::Client::ParsingError.fatal, "Parsing error is fatal"
    assert ElastomerClient::Client::SSLError.fatal, "SSL error is fatal"
    assert ElastomerClient::Client::RequestError.fatal, "Request error is fatal"
    assert ElastomerClient::Client::DocumentAlreadyExistsError.fatal, "DocumentAlreadyExistsError error is fatal"
  end

  it "has some non-fatal subclasses" do
    refute ElastomerClient::Client::TimeoutError.fatal, "Timeouts are not fatal"
    refute ElastomerClient::Client::ConnectionFailed.fatal, "Connection failures are not fatal"
    refute ElastomerClient::Client::ServerError.fatal, "Server errors are not fatal"
    refute ElastomerClient::Client::RejectedExecutionError.fatal, "Rejected execution errors are not fatal"
  end

  it "wraps illegal argument exceptions" do
    begin
      $client.get("/_cluster/health?consistency=all")

      assert false, "IllegalArgument exception was not raised"
    rescue ElastomerClient::Client::IllegalArgument => err
      assert_match(/request \[\/_cluster\/health\] contains unrecognized parameter: \[consistency\]/, err.message)
    end
  end
end

```

# test/client/index_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Index do

  before do
    @name  = "elastomer-index-test"
    @index = $client.index @name
    @index.delete if @index.exists?
  end

  after do
    @index.delete if @index.exists?
  end

  it "does not require an index name" do
    index = $client.index

    assert_nil index.name
  end

  it "determines if an index exists" do
    refute_predicate @index, :exists?, "the index should not yet exist"
  end

  it "determines if an index exists with .exist?" do
    refute_predicate @index, :exist?, "the index should not yet exist"
  end

  describe "when creating an index" do
    it "creates an index" do
      @index.create({})

      assert_predicate @index, :exists?, "the index should now exist"
    end

    it "creates an index with settings" do
      @index.create settings: { number_of_shards: 3, number_of_replicas: 0 }
      settings = @index.get_settings[@name]["settings"]

      assert_equal "3", settings["index"]["number_of_shards"]
      assert_equal "0", settings["index"]["number_of_replicas"]
    end

    it "creates an index with settings with .settings" do
      @index.create settings: { number_of_shards: 3, number_of_replicas: 0 }
      settings = @index.settings[@name]["settings"]

      assert_equal "3", settings["index"]["number_of_shards"]
      assert_equal "0", settings["index"]["number_of_replicas"]
    end

    it "adds mappings for document types" do
      @index.create(
        settings: { number_of_shards: 1, number_of_replicas: 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: false },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" }
          }
        }, true)
      )

      assert_predicate @index, :exists?, "the index should now exist"
      assert_mapping_exists @index.get_mapping[@name], "book"
    end

    it "adds mappings for document types with .mapping" do
      @index.create(
        settings: { number_of_shards: 1, number_of_replicas: 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: false },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" }
          }
        }, true)
      )

      assert_predicate @index, :exists?, "the index should now exist"
      assert_mapping_exists @index.mapping[@name], "book"
    end
  end

  it "updates index settings" do
    @index.create settings: { number_of_shards: 1, number_of_replicas: 0 }

    @index.update_settings "index.number_of_replicas" => 1
    settings = @index.settings[@name]["settings"]

    assert_equal "1", settings["index"]["number_of_replicas"]
  end

  it "updates document mappings" do
    @index.create(
      mappings: mappings_wrapper("book", {
        _source: { enabled: false },
          properties: { title: { type: "text", analyzer: "standard" } }
      }, true)
    )

    assert_property_exists @index.mapping[@name], "book", "title"

    if $client.version_support.es_version_8_plus?
      @index.update_mapping "_doc", { properties: {
        author: { type: "keyword" }
      }}
    else
      @index.update_mapping "book", { book: { properties: {
        author: { type: "keyword" }
      }}}
    end

    assert_property_exists @index.mapping[@name], "book", "author"
    assert_property_exists @index.mapping[@name], "book", "title"

    # ES8 removes mapping types so test adding a new mapping type only for versions < 8
    if !$client.version_support.es_version_8_plus?
      @index.update_mapping "mux_mool", { mux_mool: { properties: {
        song: { type: "keyword" }
      }}}

      assert_property_exists @index.mapping[@name], "mux_mool", "song"
    end
  end

  it "updates document mappings with .put_mapping" do
    @index.create(
      mappings: mappings_wrapper("book", {
        _source: { enabled: false },
          properties: { title: { type: "text", analyzer: "standard" } }
      }, true)
    )

    assert_property_exists @index.mapping[@name], "book", "title"

    if $client.version_support.es_version_8_plus?
      @index.put_mapping "_doc", { properties: {
        author: { type: "keyword" }
      }}
    else
      @index.put_mapping "book", { book: { properties: {
        author: { type: "keyword" }
      }}}
    end

    assert_property_exists @index.mapping[@name], "book", "author"
    assert_property_exists @index.mapping[@name], "book", "title"

    # ES8 removes mapping types so test adding a new mapping type only for versions < 8
    if !$client.version_support.es_version_8_plus?
      @index.put_mapping "mux_mool", { mux_mool: { properties: {
        song: { type: "keyword" }
      }}}

      assert_property_exists @index.mapping[@name], "mux_mool", "song"
    end
  end

  it "lists all aliases to the index" do
    @index.create(nil)

    assert_equal({@name => {"aliases" => {}}}, @index.get_aliases)

    $client.cluster.update_aliases add: {index: @name, alias: "foofaloo"}
    $client.cluster.update_aliases add: {index: @name, alias: "bar"}

    assert_equal({@name => {"aliases" => {"foofaloo" => {}, "bar" => {}}}}, @index.get_aliases)

    assert_equal({@name => {"aliases" => {"foofaloo" => {}}}}, @index.get_alias("f*"))
    assert_equal({@name => {"aliases" => {"foofaloo" => {}, "bar" => {}}}}, @index.get_alias("*"))

    exception = assert_raises(ElastomerClient::Client::RequestError) do
      @index.get_alias("not-there")
    end

    assert_equal("alias [not-there] missing", exception.message)
    assert_equal(404, exception.status)

    # In ES8, when you use wildcards, an error is not raised if no match is found
    if $client.version_support.es_version_8_plus?
      assert_empty(@index.get_alias("not*"))
    else
      exception = assert_raises(ElastomerClient::Client::RequestError) do
        @index.get_alias("not*")
      end

      assert_equal("alias [not*] missing", exception.message)
      assert_equal(404, exception.status)
    end
  end

  it "adds and deletes aliases to the index" do
    @index.create(nil)

    assert_empty @index.get_alias("*")

    @index.add_alias "gondolin"
    aliases = @index.get_alias("*")

    assert_equal %w[gondolin], aliases[@name]["aliases"].keys.sort

    @index.add_alias "gondor"
    aliases = @index.get_alias("*")

    assert_equal %w[gondolin gondor], aliases[@name]["aliases"].keys.sort

    @index.delete_alias "gon*"

    assert_empty @index.get_alias("*")
  end

  it "analyzes text and returns tokens" do
    tokens = @index.analyze({text: "Just a few words to analyze.", analyzer: "standard"}, index: nil)
    tokens = tokens["tokens"].map { |h| h["token"] }

    assert_equal %w[just a few words to analyze], tokens

    @index.create(
      settings: {
        number_of_shards: 1,
        number_of_replicas: 0,
        analysis: {
          analyzer: {
            english_standard: {
              type: :standard,
              stopwords: "_english_"
            }
          }
        }
      }
    )
    wait_for_index(@name)

    tokens = @index.analyze({text: "Just a few words to analyze.", analyzer: "english_standard"})
    tokens = tokens["tokens"].map { |h| h["token"] }

    assert_equal %w[just few words analyze], tokens
  end

  it "accepts a type param and does not throw an error for ES8" do
    if !$client.version_support.es_version_8_plus?
      skip "This test is only needed for ES8 onwards"
    end

    @index.create(
      mappings: mappings_wrapper("book", {
        _source: { enabled: false },
          properties: { title: { type: "text", analyzer: "standard" } }
      }, true)
    )

    assert_property_exists @index.mapping(type: "book")[@name], "book", "title"

    @index.update_mapping "book", { properties: {
      author: { type: "keyword" }
    }}

    assert_property_exists @index.mapping(type: "book")[@name], "book", "author"
    assert_property_exists @index.mapping(type: "book")[@name], "book", "title"
  end

  describe "when an index does not exist" do
    it "raises an IndexNotFoundError on delete" do
      index = $client.index("index-that-does-not-exist")
      assert_raises(ElastomerClient::Client::IndexNotFoundError) { index.delete }
    end
  end

  describe "when an index exists" do
    before do
      suggest = {
        type: "completion",
        analyzer: "simple",
        search_analyzer: "simple",
      }

      @index.create(
        settings: { number_of_shards: 1, number_of_replicas: 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" },
            suggest:
          }
        }, true)
      )
      wait_for_index(@name)
    end

    #TODO assert this only hits the desired index
    it "deletes" do
      response = @index.delete

      assert_acknowledged response
    end

    it "opens" do
      response = @index.open

      assert_acknowledged response
    end

    it "closes" do
      response = @index.close

      assert_acknowledged response
    end

    it "refreshes" do
      response = @index.refresh

      assert_equal 0, response["_shards"]["failed"]
    end

    it "flushes" do
      response = @index.flush

      assert_equal 0, response["_shards"]["failed"]
    end

    it "force merges" do
      response = @index.forcemerge

      assert_equal 0, response["_shards"]["failed"]
    end

    it "optimizes through force merge" do
      assert_equal @index.method(:forcemerge),  @index.method(:optimize)
    end

    it "recovery" do
      response = @index.recovery

      assert_includes response, "elastomer-index-test"
    end

    it "clears caches" do
      response = @index.clear_cache

      assert_equal 0, response["_shards"]["failed"]
    end

    it "gets stats" do
      response = @index.stats
      if response.key? "indices"
        assert_includes response["indices"], "elastomer-index-test"
      else
        assert_includes response["_all"]["indices"], "elastomer-index-test"
      end
    end

    it "gets segments" do
      response = @index.segments

      assert_includes response["indices"], "elastomer-index-test"
    end

    it "deletes by query" do
      @index.docs.index(document_wrapper("book", { _id: 1, title: "Book 1" }))
      @index.refresh
      r = @index.delete_by_query(q: "*")

      assert_equal(1, r["deleted"])
    end

    it "updates by query" do
      @index.docs.index(document_wrapper("book", { _id: 1, title: "Book 1" }))
      @index.refresh
      r = @index.update_by_query(
        query: { match_all: {}},
        script: { source: "ctx._source.title = 'Book 2'" }
      )

      @index.refresh
      updated = @index.docs.get(id: 1, type: "book")

      assert_equal(1, r["updated"])
      assert_equal("Book 2", updated["_source"]["title"])

      r = @index.update_by_query({
        query: { match_all: {}},
        script: { source: "ctx._source.title = 'Book 3'" }
      }, conflicts: "proceed")

      @index.refresh
      updated = @index.docs.get(id: 1, type: "book")

      assert_equal(1, r["updated"])
      assert_equal("Book 3", updated["_source"]["title"])
    end

    it "creates a Percolator" do
      id = "1"
      percolator = @index.percolator id

      assert_equal id, percolator.id
    end

    it "performs multi percolate queries" do
      # The _percolate endpoint is removed from ES8, and replaced with percolate queries via _search and _msearch
      if !$client.version_support.es_version_8_plus?
        @index.update_mapping("percolator", { properties: { query: { type: "percolator" } } })

        @index.docs.index \
          document_wrapper("book", {
            _id: 1,
            title: "Book 1 by author 1",
            author: "Author 1"
          })

        @index.docs.index \
          document_wrapper("book", {
            _id: 2,
            title: "Book 2 by author 2",
            author: "Author 2"
          })

        @index.percolator("1").create query: { match_all: { } }
        @index.percolator("2").create query: { match: { author: "Author 1" } }
        @index.refresh

        h = @index.multi_percolate(type: "book") do |m|
          m.percolate author: "Author 1"
          m.percolate author: "Author 2"
          m.count({ author: "Author 2" }, {})
        end

        response1, response2, response3 = h["responses"]

        assert_equal ["1", "2"], response1["matches"].map { |match| match["_id"] }.sort
        assert_equal ["1"], response2["matches"].map { |match| match["_id"] }.sort
        assert_equal 1, response3["total"]
      end
    end

    it "performs suggestion queries" do
      # The _suggest endpoint is removed from ES8, suggest functionality is now via _search
      if !$client.version_support.es_version_8_plus?
        @index.docs.index \
          document_wrapper("book", {
            _id: 1,
            title: "the magnificent",
            author: "greg",
            suggest: {input: "greg", weight: 2}
          })

        @index.docs.index \
          document_wrapper("book", {
            _id: 2,
            title: "the author of rubber-band",
            author: "grant",
            suggest: {input: "grant", weight: 1}
          })
        @index.refresh
        response = @index.suggest({name: {text: "gr", completion: {field: :suggest}}})

        assert response.key?("name")
        hash = response["name"].first

        assert_equal "gr", hash["text"]

        options = hash["options"]

        assert_equal 2, options.length
        assert_equal "greg", options.first["text"]
        assert_equal "grant", options.last["text"]
      end
    end

    it "handles output parameter of field" do
      document = document_wrapper("book", {
        _id:     1,
        title:   "the magnificent",
        author:  "greg",
        suggest: {input: %w[Greg greg], output: "Greg", weight: 2}
      })

      # Indexing the document fails when `output` is provided
      exception = assert_raises(ElastomerClient::Client::RequestError) do
        @index.docs.index(document)
      end

      assert_equal(400, exception.status)
      assert_match(/\[output\]/, exception.message)
    end
  end
end

```

# test/client/multi_percolate_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::MultiPercolate do

  before do
    if $client.version_support.es_version_8_plus?
      skip "Multi percolate not supported in ES version #{$client.version}"
    end

    @name  = "elastomer-mpercolate-test"
    @index = $client.index(@name)

    unless @index.exists?
      base_mappings_settings = {
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: {
          doc1: {
            _source: { enabled: true }, _all: { enabled: false },
            properties: {
              title: { type: "text", analyzer: "standard" },
              author: { type: "keyword" }
            }
          },
          doc2: {
            _source: { enabled: true }, _all: { enabled: false },
            properties: {
              title: { type: "text", analyzer: "standard" },
              author: { type: "keyword" }
            }
          }
        }
      }

      base_mappings_settings[:mappings][:percolator] = { properties: { query: { type: "percolator" } } }

      @index.create base_mappings_settings
      wait_for_index(@name)
    end

    @docs = @index.docs
  end

  after do
    @index.delete if @index.exists?
  end

  it "performs multi percolate queries" do
    populate!

    body = [
      '{"percolate" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "pea53"}}',
      '{"percolate" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "grantr"}}',
      '{"count" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "grantr"}}',
      nil
    ]
    body = body.join "\n"
    h = $client.multi_percolate body
    response1, response2, response3 = h["responses"]

    assert_equal ["1", "2"], response1["matches"].map { |match| match["_id"] }.sort
    assert_equal ["1", "3"], response2["matches"].map { |match| match["_id"] }.sort
    assert_equal 2, response3["total"]
  end

  it "performs multi percolate queries with .mpercolate" do
    populate!

    body = [
      '{"percolate" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "pea53"}}',
      '{"percolate" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "grantr"}}',
      '{"count" : {"index": "elastomer-mpercolate-test", "type": "doc2"}}',
      '{"doc": {"author": "grantr"}}',
      nil
    ]
    body = body.join "\n"
    h = $client.mpercolate body
    response1, response2, response3 = h["responses"]

    assert_equal ["1", "2"], response1["matches"].map { |match| match["_id"] }.sort
    assert_equal ["1", "3"], response2["matches"].map { |match| match["_id"] }.sort
    assert_equal 2, response3["total"]
  end

  it "supports a nice block syntax" do
    populate!

    h = $client.multi_percolate(index: @name, type: "doc2") do |m|
      m.percolate author: "pea53"
      m.percolate author: "grantr"
      m.count({ author: "grantr" })
    end

    response1, response2, response3 = h["responses"]

    assert_equal ["1", "2"], response1["matches"].map { |match| match["_id"] }.sort
    assert_equal ["1", "3"], response2["matches"].map { |match| match["_id"] }.sort
    assert_equal 2, response3["total"]
  end

  def populate!
    @docs.index \
      _id: 1,
      _type: "doc1",
      title: "the author of gravatar",
      author: "mojombo"

    @docs.index \
      _id: 2,
      _type: "doc1",
      title: "the author of resque",
      author: "defunkt"

    @docs.index \
      _id: 1,
      _type: "doc2",
      title: "the author of logging",
      author: "pea53"

    @docs.index \
      _id: 2,
      _type: "doc2",
      title: "the author of rubber-band",
      author: "grantr"

    percolator1 = @index.percolator "1"
    percolator1.create query: { match_all: { } }
    percolator2 = @index.percolator "2"
    percolator2.create query: { match: { author: "pea53" } }
    percolator2 = @index.percolator "3"
    percolator2.create query: { match: { author: "grantr" } }

    @index.refresh
  end
  # rubocop:enable Metrics/MethodLength
end

```

# test/client/multi_search_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::MultiSearch do

  before do
    @name  = "elastomer-msearch-test"
    @index = $client.index(@name)

    unless @index.exists?
      @index.create \
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" }
          }
        }, !$client.version_support.es_version_8_plus?)
      wait_for_index(@name)
    end

    @docs = @index.docs
  end

  after do
    @index.delete if @index.exists?
  end

  it "performs multisearches" do
    populate!

    body = [
      '{"index" : "elastomer-msearch-test"}',
      '{"query" : {"match_all" : {}}}',
      '{"index" : "elastomer-msearch-test"}',
      '{"query" : {"match": {"author" : "Author 2"}}}',
      nil
    ]
    body = body.join "\n"
    h = $client.multi_search body
    response1, response2 = h["responses"]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response1["hits"]["total"]["value"]
      assert_equal 1, response2["hits"]["total"]["value"]
    else
      assert_equal 2, response1["hits"]["total"]
      assert_equal 1, response2["hits"]["total"]
    end

    assert_equal "2", response2["hits"]["hits"][0]["_id"]

    body = [
      "{}",
      '{"query" : {"match": {"author" : "Author 2"}}}',
      nil
    ]
    body = body.join "\n"
    h = $client.multi_search body, index: @name
    response1 = h["responses"].first

    if $client.version_support.es_version_8_plus?
      assert_equal 1, response1["hits"]["total"]["value"]
    else
      assert_equal 1, response1["hits"]["total"]
    end

    assert_equal "2", response1["hits"]["hits"][0]["_id"]
  end

  it "performs multisearches with .msearch" do
    populate!

    body = [
      '{"index" : "elastomer-msearch-test"}',
      '{"query" : {"match_all" : {}}}',
      '{"index" : "elastomer-msearch-test"}',
      '{"query" : {"match": {"author" : "Author 2"}}}',
      nil
    ]
    body = body.join "\n"
    h = $client.msearch body
    response1, response2 = h["responses"]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response1["hits"]["total"]["value"]
      assert_equal 1, response2["hits"]["total"]["value"]
    else
      assert_equal 2, response1["hits"]["total"]
      assert_equal 1, response2["hits"]["total"]
    end

    assert_equal "2", response2["hits"]["hits"][0]["_id"]

    body = [
      "{}",
      '{"query" : {"match": {"author" : "Author 2"}}}',
      nil
    ]
    body = body.join "\n"
    h = $client.msearch body, index: @name
    response1 = h["responses"].first

    if $client.version_support.es_version_8_plus?
      assert_equal 1, response1["hits"]["total"]["value"]
    else
      assert_equal 1, response1["hits"]["total"]
    end

    assert_equal "2", response1["hits"]["hits"][0]["_id"]
  end

  it "supports a nice block syntax" do
    populate!

    h = $client.multi_search do |m|
      m.search({query: { match_all: {}}}, index: @name)
      m.search({query: { match: { "title" => "author" }}}, index: @name)
    end

    response1, response2 = h["responses"]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response1["hits"]["total"]["value"]
      assert_equal 2, response2["hits"]["total"]["value"]
    else
      assert_equal 2, response1["hits"]["total"]
      assert_equal 2, response2["hits"]["total"]
    end

    h = @index.multi_search do |m|
      m.search({query: { match_all: {}}})
      m.search({query: { match: { "title" => "author" }}})
    end

    response1, response2 = h["responses"]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response1["hits"]["total"]["value"]
      assert_equal 2, response2["hits"]["total"]["value"]
    else
      assert_equal 2, response1["hits"]["total"]
      assert_equal 2, response2["hits"]["total"]
    end

    type = $client.version_support.es_version_8_plus? ? "" : "book"
    h = @index.docs(type).multi_search do |m|
      m.search({query: { match_all: {}}})
      m.search({query: { match: { "title" => "2" }}})
    end

    response1, response2 = h["responses"]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response1["hits"]["total"]["value"]
      assert_equal 1, response2["hits"]["total"]["value"]
    else
      assert_equal 2, response1["hits"]["total"]
      assert_equal 1, response2["hits"]["total"]
    end
  end

  it "performs suggestion queries using the search endpoint" do
    populate!

    h = @index.multi_search do |m|
      m.search({
        query: {
          match: {
            title: "by author"
          }
        },
        suggest: {
          suggestion1: {
            text: "by author",
            term: {
              field: "author"
            }
          }
        }
      })
    end

    response = h["responses"][0]

    if $client.version_support.es_version_8_plus?
      assert_equal 2, response["hits"]["total"]["value"]
    else
      assert_equal 2, response["hits"]["total"]
    end

    refute_nil response["suggest"], "expected suggester text to be returned"
  end

  def populate!
    @docs.index \
      document_wrapper("book", {
        _id: 1,
        title: "Book 1 by author 1",
        author: "Author 1"
      })

    @docs.index \
      document_wrapper("book", {
        _id: 2,
        title: "Book 2 by author 2",
        author: "Author 2"
      })

    @index.refresh
  end
  # rubocop:enable Metrics/MethodLength
end

```

# test/client/native_delete_by_query_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::NativeDeleteByQuery do
  before do
    @index = $client.index "elastomer-delete-by-query-test"
    @index.delete if @index.exists?
    @docs = @index.docs("docs")
  end

  after do
    @index.delete if @index.exists?
  end

  describe "when an index with documents exists" do
    before do
      @index.create(nil)
      wait_for_index(@index.name)
    end

    it "deletes by query" do
      @docs.index({ _id: 0, name: "mittens" })
      @docs.index({ _id: 1, name: "luna" })

      @index.refresh

      query = {
        query: {
          match: {
            name: "mittens"
          }
        }
      }

      response = @index.native_delete_by_query(query)

      refute_nil response["took"]
      refute(response["timed_out"])
      assert_equal(1, response["batches"])
      assert_equal(1, response["total"])
      assert_equal(1, response["deleted"])
      assert_empty(response["failures"])

      @index.refresh
      response = @docs.multi_get(ids: [0, 1])

      refute_found response.fetch("docs")[0]
      assert_found response.fetch("docs")[1]
    end

    it "fails when internal version is 0" do
      if $client.version_support.es_version_8_plus?
        skip "Concurrency control with internal version is not supported in ES #{$client.version}"
      end
      @docs.index({_id: 0, name: "mittens"})
      # Creating a document with external version 0 also sets the internal version to 0
      # Otherwise you can't index a document with version 0.
      @docs.index({_id: 1, _version: 0, _version_type: "external", name: "mittens"})
      @index.refresh

      query = {
        query: {
          match: {
            name: "mittens"
          }
        }
      }

      assert_raises(ElastomerClient::Client::RequestError) do
        @index.native_delete_by_query(query)
      end
    end

    it "fails when an unknown parameter is provided" do
      assert_raises(ElastomerClient::Client::IllegalArgument) do
        @index.native_delete_by_query({}, foo: "bar")
      end
    end

    it "deletes by query when routing is specified" do
      index = $client.index "elastomer-delete-by-query-routing-test"
      index.delete if index.exists?
      type = "docs"
      # default number of shards in ES8 is 1, so set it to 2 shards so routing to different shards can be tested
      settings = $client.version_support.es_version_8_plus? ? { number_of_shards: 2 } : {}
      index.create({
        settings:,
        mappings: mappings_wrapper(type, {
          properties: {
            name: { type: "text", analyzer: "standard" },
          },
          _routing: { required: true }
        })
      })
      wait_for_index(@index.name)
      docs = index.docs(type)

      docs.index({ _id: 0, _routing: "cat", name: "mittens" })
      docs.index({ _id: 1, _routing: "cat", name: "luna" })
      docs.index({ _id: 2, _routing: "dog", name: "mittens" })

      query = {
        query: {
          match: {
            name: "mittens"
          }
        }
      }

      index.refresh
      response = index.native_delete_by_query(query, routing: "cat")

      assert_equal(1, response["deleted"])

      response = docs.multi_get({
        docs: [
          { _id: 0, routing: "cat" },
          { _id: 1, routing: "cat" },
          { _id: 2, routing: "dog" },
        ]
      })

      refute_found response["docs"][0]
      assert_found response["docs"][1]
      assert_found response["docs"][2]

      index.delete if index.exists?
    end
  end
end

```

# test/client/nodes_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Nodes do

  it "gets info for the node(s)" do
    h = $client.nodes.info

    assert h.key?("cluster_name"), "the cluster name is returned"
    assert_instance_of Hash, h["nodes"], "the node list is returned"
  end

  it "gets stats for the node(s)" do
    h = $client.nodes.stats

    assert_instance_of Hash, h["nodes"], "the node list is returned"

    node = h["nodes"].values.first

    assert node.key?("indices"), "indices stats are returned"
  end

  it "filters node info" do
    h = $client.nodes.info(info: "os")
    node = h["nodes"].values.first

    assert node.key?("os"), "expected os info to be present"
    refute node.key?("jvm"), "expected jvm info to be absent"

    h = $client.nodes.info(info: %w[jvm process])
    node = h["nodes"].values.first

    assert node.key?("jvm"), "expected jvm info to be present"
    assert node.key?("process"), "expected process info to be present"
    refute node.key?("network"), "expected network info to be absent"
  end

  it "filters node stats" do
    h = $client.nodes.stats(stats: "http")
    node = h["nodes"].values.first

    assert node.key?("http"), "expected http stats to be present"
    refute node.key?("indices"), "expected indices stats to be absent"
  end

  it "gets the hot threads for the node(s)" do
    str = $client.nodes.hot_threads read_timeout: 2

    assert_instance_of String, str
    refute_nil str, "expected response to not be nil"
    refute_empty str, "expected response to not be empty"
  end

  it "can be scoped to a single node" do
    h = $client.nodes("node-with-no-name").info

    assert_empty h["nodes"]
  end

  it "can be scoped to multiple nodes" do
    h = $client.nodes(%w[node1 node2 node3]).info

    assert_empty h["nodes"]
  end

end

```

# test/client/percolator_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Percolator do

  before do
    if $client.version_support.es_version_8_plus?
      skip "Percolate not supported in ES version #{$client.version}"
    end

    @index = $client.index "elastomer-percolator-test"
    @index.delete if @index.exists?
    @docs = @index.docs("docs")
  end

  after do
    @index.delete if @index.exists?
  end

  describe "when an index exists" do
    before do
      base_mappings = { mappings: { percolator: { properties: { query: { type: "percolator" } } } } }

      @index.create(base_mappings)
      wait_for_index(@index.name)
    end

    it "creates a query" do
      percolator = @index.percolator "1"
      response = percolator.create query: { match_all: { } }

      assert response["created"], "Couldn't create the percolator query"
    end

    it "gets a query" do
      percolator = @index.percolator "1"
      percolator.create query: { match_all: { } }
      response = percolator.get

      assert response["found"], "Couldn't find the percolator query"
    end

    it "deletes a query" do
      percolator = @index.percolator "1"
      percolator.create query: { match_all: { } }
      response = percolator.delete

      assert response["found"], "Couldn't find the percolator query"
    end

    it "checks for the existence of a query" do
      percolator = @index.percolator "1"

      refute_predicate percolator, :exists?, "Percolator query exists"
      percolator.create query: { match_all: { } }

      assert_predicate percolator, :exists?, "Percolator query does not exist"
    end

    it "cannot delete all percolators by providing a nil id" do
      assert_raises(ArgumentError) { @index.percolator nil }
    end
  end
end

```

# test/client/reindex_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Reindex do
  before do
    @source_index = $client.index("source_index")
    @dest_index = $client.index("dest_index")
    @non_existent_index = $client.index("non_existent_index")
    if @source_index.exists?
      @source_index.delete
    end
    if @dest_index.exists?
      @dest_index.delete
    end
    if @non_existent_index.exists?
      @non_existent_index.delete
    end
    @source_index.create(default_index_settings)
    @dest_index.create(default_index_settings)
    wait_for_index(@source_index.name, "green")
    wait_for_index(@dest_index.name, "green")

    # Index a document in the source index
    @source_index.docs.index(document_wrapper("book", { _id: 1, title: "Book 1" }))
    @source_index.refresh
  end

  after do
    @source_index.delete if @source_index.exists?
    @dest_index.delete if @dest_index.exists?
    @non_existent_index.delete if @non_existent_index.exists?
  end

  it "reindexes documents from one index to another" do
    reindex = $client.reindex
    body = {
      source: { index: @source_index.name },
      dest: { index: @dest_index.name }
    }
    reindex.reindex(body)

    # Refresh the destination index to make sure the document is searchable
    @dest_index.refresh

    # Verify that the document has been reindexed
    doc = @dest_index.docs.get(id: 1, type: "book")

    assert_equal "Book 1", doc["_source"]["title"]
  end

  it "successfully rethrottles a reindex task" do
    reindex = $client.reindex
    body = {
      source: { index: @source_index.name },
      dest: { index: @dest_index.name }
    }
    response = reindex.reindex(body, requests_per_second: 0.01, wait_for_completion: false)
    task_id = response["task"]
    node_id = task_id.split(":").first
    task_number = task_id.split(":").last.to_i

    response = reindex.rethrottle(task_id, requests_per_second: 1)

    assert_equal 1, response["nodes"][node_id]["tasks"][task_id]["status"]["requests_per_second"]

    # wait for the task to complete
    tasks = $client.tasks
    tasks.wait_by_id(node_id, task_number, "30s")

    # Verify that the document has been reindexed
    doc = @dest_index.docs.get(id: 1, type: "book")

    assert_equal "Book 1", doc["_source"]["title"]
  end

  it "creates a new index when the destination index does not exist" do
    reindex = $client.reindex
    body = {
      source: { index: @source_index.name },
      dest: { index: "non_existent_index" }
    }
    reindex.reindex(body)
    new_index = $client.index("non_existent_index")

    assert_predicate(new_index, :exists?)
  end

  it "fails when the source index does not exist" do
    reindex = $client.reindex
    body = {
      source: { index: "non_existent_index" },
      dest: { index: @dest_index.name }
    }

    exception = assert_raises(ElastomerClient::Client::RequestError) do
      reindex.reindex(body)
    end
    assert_equal(404, exception.status)
  end
end

```

# test/client/repository_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Repository do
  before do
    if !run_snapshot_tests?
      skip "To enable snapshot tests, add a path.repo setting to your elasticsearch.yml file."
    end

    @name = "elastomer-repository-test"
    @repo = $client.repository(@name)
  end

  it "determines if a repo exists" do
    refute_predicate @repo, :exists?
    refute_predicate @repo, :exist?
    with_tmp_repo(@name) do
      assert_predicate @repo, :exists?
    end
  end

  it "creates repos" do
    response = create_repo(@name)

    assert response["acknowledged"]
    delete_repo(@name)
  end

  it "cannot create a repo without a name" do
    _(lambda {
      create_repo(nil)
    }).must_raise ArgumentError
  end

  it "gets repos" do
    with_tmp_repo do |repo|
      response = repo.get

      refute_nil response[repo.name]
    end
  end

  it "gets all repos" do
    with_tmp_repo do |repo|
      response = $client.repository.get

      refute_nil response[repo.name]
    end
  end

  it "gets repo status" do
    with_tmp_repo do |repo|
      response = repo.status

      assert_empty response["snapshots"]
    end
  end

  it "gets status of all repos" do
    response = $client.repository.status

    assert_empty response["snapshots"]
  end

  it "updates repos" do
    with_tmp_repo do |repo|
      settings = repo.get[repo.name]["settings"]
      response = repo.update(type: "fs", settings: settings.merge("compress" => true))

      assert response["acknowledged"]
      assert_equal "true", repo.get[repo.name]["settings"]["compress"]
    end
  end

  it "cannot update a repo without a name" do
    with_tmp_repo do |repo|
      _(lambda {
        settings = repo.get[repo.name]["settings"]
        $client.repository.update(type: "fs", settings: settings.merge("compress" => true))
      }).must_raise ArgumentError
    end
  end

  it "deletes repos" do
    with_tmp_repo do |repo|
      response = repo.delete

      assert response["acknowledged"]
      refute_predicate repo, :exists?
    end
  end

  it "cannot delete a repo without a name" do
    _(lambda {
      $client.repository.delete
    }).must_raise ArgumentError
  end

  it "gets snapshots" do
    with_tmp_repo do |repo|
      response = repo.snapshots.get

      assert_empty response["snapshots"]

      create_snapshot(repo, "test-snapshot")
      response = repo.snapshot.get

      assert_equal ["test-snapshot"], response["snapshots"].collect { |info| info["snapshot"] }

      create_snapshot(repo, "test-snapshot2")
      response  = repo.snapshots.get
      snapshot_names = response["snapshots"].collect { |info| info["snapshot"] }

      assert_includes snapshot_names, "test-snapshot"
      assert_includes snapshot_names, "test-snapshot2"
    end
  end
end

```

# test/client/rest_api_spec/api_spec_test.rb

```rb
# frozen_string_literal: true

require_relative "../../test_helper"

describe ElastomerClient::Client::RestApiSpec::ApiSpec do
  before do
    @api_spec = ElastomerClient::Client::RestApiSpec.api_spec("5.6.4")
  end

  it "selects valid path parts" do
    parts  = {:index => "test", "type" => "doc", :foo => "bar"}
    result = @api_spec.select_parts(api: "search", from: parts)

    assert_equal({:index => "test", "type" => "doc"}, result)
  end

  it "identifies valid path parts" do
    assert @api_spec.valid_part?(api: "search", part: "index")
    assert @api_spec.valid_part?(api: "search", part: :type)
    refute @api_spec.valid_part?(api: "search", part: :id)
  end

  it "selects valid request params" do
    params = {:explain => true, "preference" => "local", :nope => "invalid"}
    result = @api_spec.select_params(api: "search", from: params)

    assert_equal({:explain => true, "preference" => "local"}, result)
  end

  it "identifies valid request params" do
    assert @api_spec.valid_param?(api: "search", param: "explain")
    assert @api_spec.valid_param?(api: "search", param: :preference)
    assert @api_spec.valid_param?(api: "search", param: :routing)
    refute @api_spec.valid_param?(api: "search", param: "pretty")
  end

  it "selects common request params" do
    params = {:pretty => true, "human" => true, :nope => "invalid"}
    result = @api_spec.select_common_params(from: params)

    assert_equal({:pretty => true, "human" => true}, result)
  end

  it "identifies common request params" do
    assert @api_spec.valid_common_param?("pretty")
    assert @api_spec.valid_common_param?(:human)
    assert @api_spec.valid_common_param?(:source)
    refute @api_spec.valid_common_param?("nope")
  end

  it "validates request params" do
    params = {q: "*:*", pretty: true, "nope": false}
    assert_raises(ElastomerClient::Client::IllegalArgument, "'nope' is not a valid parameter for the 'search' API") {
      @api_spec.validate_params!(api: "search", params:)
    }
  end
end

```

# test/client/rest_api_spec/rest_api_test.rb

```rb
# frozen_string_literal: true

require_relative "../../test_helper"

describe ElastomerClient::Client::RestApiSpec::RestApi do
  before do
    @rest_api = ElastomerClient::Client::RestApiSpec::RestApi.new \
        documentation: "https://www.elastic.co/guide/en/elasticsearch/reference/5.x/cluster-state.html",
        methods: ["GET"],
        body: nil,
        url: {
          path: "/_cluster/state",
          paths: ["/_cluster/state", "/_cluster/state/{metric}", "/_cluster/state/{metric}/{index}"],
          parts: {
            "index" => {"type"=>"list", "description"=>"A comma-separated list of index names; use `_all` or empty string to perform the operation on all indices"},
            "metric" => {"type"=>"list", "options"=>["_all", "blocks", "metadata", "nodes", "routing_table", "routing_nodes", "master_node", "version"], "description"=>"Limit the information returned to the specified metrics"},
          },
          params: {
            "local" => {"type"=>"boolean", "description"=>"Return local information, do not retrieve the state from master node (default: false)"},
            "master_timeout" => {"type"=>"time", "description"=>"Specify timeout for connection to master"},
            "flat_settings" => {"type"=>"boolean", "description"=>"Return settings in flat format (default: false)"},
            "ignore_unavailable" => {"type"=>"boolean", "description"=>"Whether specified concrete indices should be ignored when unavailable (missing or closed)"},
            "allow_no_indices" => {"type"=>"boolean", "description"=>"Whether to ignore if a wildcard indices expression resolves into no concrete indices. (This includes `_all` string or when no indices have been specified)"},
            "expand_wildcards" => {"type"=>"enum", "options"=>["open", "closed", "none", "all"], "default"=>"open", "description"=>"Whether to expand wildcard expression to concrete indices that are open, closed or both."},
          }
        }
  end

  it "selects valid path parts" do
    hash = {
      :index => "test",
      "metric" => "os",
      :nope => "not selected"
    }
    selected = @rest_api.select_parts(from: hash)

    refute selected.key?(:nope)
    assert selected.key?(:index)
    assert selected.key?("metric")
  end

  it "identifies valid parts" do
    assert @rest_api.valid_part? :index
    assert @rest_api.valid_part? "metric"
    refute @rest_api.valid_part? :nope
  end

  it "selects valid request params" do
    hash = {
      :local => true,
      "flat_settings" => true,
      :expand_wildcards => "all",
      :nope => "not selected"
    }
    selected = @rest_api.select_params(from: hash)

    refute selected.key?(:nope)
    assert selected.key?(:local)
    assert selected.key?("flat_settings")
    assert selected.key?(:expand_wildcards)
  end

  it "identifies valid params" do
    assert @rest_api.valid_param? :local
    assert @rest_api.valid_param? "flat_settings"
    refute @rest_api.valid_param? :nope
  end

  it "accesses the documentation url" do
    assert_equal "https://www.elastic.co/guide/en/elasticsearch/reference/5.x/cluster-state.html", @rest_api.documentation
  end

  it "exposes the HTTP methods as an Array" do
    assert_equal %w[GET], @rest_api.methods
  end

  it "accesses the body settings" do
    assert_nil @rest_api.body
  end

  describe "accessing the url" do
    it "accesses the path" do
      assert_equal "/_cluster/state", @rest_api.url.path
    end

    it "exposes the paths as an Array" do
      assert_equal %w[/_cluster/state /_cluster/state/{metric} /_cluster/state/{metric}/{index}], @rest_api.url.paths
    end

    it "accesses the path parts" do
      assert_equal %w[index metric], @rest_api.url.parts.keys
    end

    it "accesses the request params" do
      assert_equal %w[local master_timeout flat_settings ignore_unavailable allow_no_indices expand_wildcards], @rest_api.url.params.keys
    end
  end
end

```

# test/client/scroller_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Scroller do

  before do
    @name  = "elastomer-scroller-test"
    @index = $client.index(@name)
    @type =  $client.version_support.es_version_8_plus? ? "_doc" : "book"

    unless @index.exists?
      @index.create \
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "text", analyzer: "standard" },
            author: { type: "keyword" },
            sorter: { type: "integer" }
          }
        }, true)

      wait_for_index(@name)
      populate!
    end
  end

  after do
    @index.delete if @index.exists?
  end

  it "scans over all documents in an index" do
    scan = @index.scan '{"query":{"match_all":{}}}', size: 10

    count = 0
    scan.each_document { |h| count += 1 }

    assert_equal 25, count
  end

  it "limits results by query" do
    scan = @index.scan query: { bool: { should: [
      {match: {title: "17"}}
    ]}}

    count = 0
    scan.each_document { |h| count += 1 }

    assert_equal 1, count
  end

  it "scrolls and sorts over all documents" do
    scroll = @index.scroll({
      query: {match_all: {}},
      sort: {sorter: {order: :asc}}
    }, type: @type)

    books = []
    scroll.each_document { |h| books << h["_id"].to_i }

    expected = (0...25).to_a.reverse

    assert_equal expected, books
  end

  it "propagates URL query strings" do
    scan = @index.scan(nil, { q: "title:1 || title:17" })

    count = 0
    scan.each_document { |h| count += 1 }

    assert_equal 2, count
  end

  it "clears one or more scroll IDs" do
    h = $client.start_scroll \
      body: {query: {match_all: {}}},
      index: @index.name,
      type: @type,
      scroll: "1m",
      size: 10

    refute_nil h["_scroll_id"], "response is missing a scroll ID"

    response = $client.clear_scroll(h["_scroll_id"])

    assert response["succeeded"]
    assert_equal 1, response["num_freed"]
  end

  it "raises an exception on existing sort in query" do
    assert_raises(ArgumentError) { @index.scan sort: [:_doc] , query: {} }
  end

  def populate!
    h = @index.bulk do |b|
      25.times { |num|
        if $client.version_support.es_version_8_plus?
          b.index %Q({"author":"Pratchett","title":"DiscWorld Book #{num}","sorter":#{25-num}}), _id: num
        else
          b.index %Q({"author":"Pratchett","title":"DiscWorld Book #{num}","sorter":#{25-num}}), _id: num, _type: "book"
        end
      }
    end

    h["items"].each { |item| assert_bulk_index(item) }

    @index.refresh
  end
end

```

# test/client/snapshot_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Snapshot do
  before do
    @index = nil
    @restored_index = nil

    if !run_snapshot_tests?
      skip "To enable snapshot tests, add a path.repo setting to your elasticsearch.yml file."
    end

    @index_name = "elastomer-snapshot-test-index"
    @index = $client.index(@index_name)
    @name = "elastomer-test"
    if $client.version_support.es_version_8_plus?
      $client.cluster.update_settings persistent: { "ingest.geoip.downloader.enabled" => "false" }
    end
  end

  after do
    @index.delete if @index && @index.exists?
  end

  it "determines if a snapshot exists" do
    with_tmp_repo do |repo|
      snapshot = repo.snapshot(@name)

      refute_predicate snapshot, :exists?
      refute_predicate snapshot, :exist?
      snapshot.create({}, wait_for_completion: true)

      assert_predicate snapshot, :exist?
    end
  end

  it "creates snapshots" do
    with_tmp_repo do |repo|
      response = repo.snapshot(@name).create({}, wait_for_completion: true)

      assert_equal @name, response["snapshot"]["snapshot"]
    end
  end

  it "creates snapshots with options" do
    @index.create(settings: { number_of_shards: 1, number_of_replicas: 0 })
    with_tmp_repo do |repo|
      response = repo.snapshot(@name).create({ indices: [@index_name] }, wait_for_completion: true)

      assert_equal [@index_name], response["snapshot"]["indices"]
      assert_equal 1, response["snapshot"]["shards"]["total"]
    end
  end

  it "gets snapshot info for one and all" do
    with_tmp_snapshot do |snapshot, repo|
      response = snapshot.get

      assert_equal snapshot.name, response["snapshots"][0]["snapshot"]
      response = repo.snapshots.get

      assert_equal snapshot.name, response["snapshots"][0]["snapshot"]
    end
  end

  it "gets snapshot status for one and all" do
    @index.create(settings: { number_of_shards: 1, number_of_replicas: 0 })
    with_tmp_repo do |repo|
      repo.snapshot(@name).create({indices: [@index_name]}, wait_for_completion: true)
      response = repo.snapshot(@name).status

      assert_equal 1, response["snapshots"][0]["shards_stats"]["total"]
    end
  end

  it "gets status of snapshots in progress" do
    # we can't reliably get status of an in-progress snapshot in tests, so
    # check for an empty result instead
    with_tmp_repo do |repo|
      response = repo.snapshots.status

      assert_empty response["snapshots"]
      response = $client.snapshot.status

      assert_empty response["snapshots"]
    end
  end

  it "disallows nil repo name with non-nil snapshot name" do
    assert_raises(ArgumentError) { $client.repository.snapshot("snapshot") }
    assert_raises(ArgumentError) { $client.snapshot(nil, "snapshot") }
  end

  it "deletes snapshots" do
    with_tmp_snapshot do |snapshot|
      response = snapshot.delete

      assert response["acknowledged"]
    end
  end

  it "restores snapshots" do
    @index.create(settings: { number_of_shards: 1, number_of_replicas: 0 })
    wait_for_index(@index_name)
    with_tmp_repo do |repo|
      snapshot = repo.snapshot(@name)
      snapshot.create({ indices: [@index_name] }, wait_for_completion: true)
      @index.delete
      response = snapshot.restore({}, wait_for_completion: true)

      assert_equal 1, response["snapshot"]["shards"]["total"]
    end
  end

  describe "restoring to a different index" do
    before do
      @restored_index_name = "#{@index_name}-restored"
      @restored_index = $client.index(@restored_index_name)
    end

    after do
      @restored_index.delete if @restored_index && @restored_index.exists?
    end

    it "restores snapshots with options" do
      @index.create(settings: { number_of_shards: 1, number_of_replicas: 0 })
      wait_for_index(@index_name)
      with_tmp_repo do |repo|
        snapshot = repo.snapshot(@name)
        snapshot.create({indices: [@index_name]}, wait_for_completion: true)
        response = snapshot.restore({
          rename_pattern: @index_name,
          rename_replacement: @restored_index_name
        }, wait_for_completion: true)

        assert_equal [@restored_index_name], response["snapshot"]["indices"]
        assert_equal 1, response["snapshot"]["shards"]["total"]
      end
    end
  end
end

```

# test/client/stubbed_client_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe "stubbed client tests" do
  before do
    @stubs  = Faraday::Adapter.lookup_middleware(:test)::Stubs.new
    @client = ElastomerClient::Client.new adapter: [:test, @stubs]
    @client.instance_variable_set(:@version, "5.6.4")
  end

  describe ElastomerClient::Client::Cluster do
    it "reroutes shards" do
      @stubs.post "/_cluster/reroute?dry_run=true" do |env|
        assert_match %r/^\{"commands":\[\{"move":\{[^\{\}]+\}\}\]\}$/, env[:body]
        [200, {"Content-Type" => "application/json"}, '{"acknowledged" : true}']
      end

      commands = { move: { index: "test", shard: 0, from_node: "node1", to_node: "node2" }}
      h = @client.cluster.reroute commands, dry_run: true

      assert_acknowledged h
    end
  end
end

```

# test/client/tasks_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Tasks do
  before do
    @tasks = $client.tasks

    @index = $client.index("elastomer-tasks-test")
    @index.create(default_index_settings)
    wait_for_index(@index.name)
  end

  after do
    @index.delete if @index.exists?
  end

  it "list all in-flight tasks" do
    h = @tasks.get

    assert_operator h["nodes"].keys.size, :>, 0

    total_tasks = h["nodes"].map { |k, v| v["tasks"].keys.count }.sum

    assert_operator total_tasks, :>, 0
  end

  it "groups by parent->child relationships when get-all tasks API is grouped by 'parents'" do
    h = @tasks.get group_by: "parents"
    parent_id = h["tasks"].select { |k, v| v.key?("children") }.keys.first
    childs_parent_ref = h.dig("tasks", parent_id, "children").first["parent_task_id"]

    assert_equal parent_id, childs_parent_ref
  end

  it "raises exception when get_by_id is called without required task & node IDs" do
    assert_raises(ArgumentError) do
      @tasks.get_by_id
    end
  end

  it "raises exception when get_by_id is called w/invalid task ID is supplied" do
    node_id = @tasks.get["nodes"].map { |k, v| k }.first
    assert_raises(ArgumentError) do
      @tasks.get_by_id node_id, "task_id_should_be_integer"
    end
  end

  it "raises exception when get_by_id is called w/invalid node ID is supplied" do
    assert_raises(ArgumentError) do
      @tasks.get_by_id nil, 42
    end
  end

  it "successfully waits for task to complete when wait_for_completion and timeout flags are set" do
    test_thread = nil
    begin
      # poulate the index in a background thread to generate long-running tasks we can query
      test_thread = populate_background_index!(@index.name)

      # ensure we can wait on completion of a task
      success = false
      query_long_running_tasks.each do |ts|
        t = ts.values.first
        begin
          resp = @tasks.wait_by_id t["node"], t["id"], "3s"
          success = !resp.key?("node_failures")
        rescue ElastomerClient::Client::ServerError => e
          # this means the timeout expired before the task finished, but it's a good thing!
          success = /Timed out waiting for completion/ =~ e.message
        end
        break if success
      end

      assert success
    ensure
      test_thread.join unless test_thread.nil?
    end
  end

  it "locates the task properly by ID when valid node and task IDs are supplied" do
    test_thread = nil
    begin
      # make an index with a new client (in this thread, to avoid query check race after)
      # poulate the index in a background thread to generate long-running tasks we can query
      test_thread = populate_background_index!(@index.name)

      # look up and verify found task
      found_by_id = false
      query_long_running_tasks.each do |ts|
        t = ts.values.first
        resp = @tasks.get_by_id t["node"], t["id"]

        found_by_id = resp["task"]["node"] == t["node"] && resp["task"]["id"] == t["id"]

        break if found_by_id
      end

      assert found_by_id
    ensure
      test_thread.join unless test_thread.nil?
    end
  end

  it "raises exception when cancel_by_id is called without required task & node IDs" do
    assert_raises(ArgumentError) do
      @tasks.cancel_by_id
    end
  end

  it "raises exception when cancel_by_id is called w/invalid task ID is supplied" do
    node_id = @tasks.get["nodes"].map { |k, v| k }.first
    assert_raises(ArgumentError) do
      @tasks.cancel_by_id node_id, "not_an_integer_id"
    end
  end

  it "raises exception when cancel_by_id is called w/invalid node IDs is supplied" do
    assert_raises(ArgumentError) do
      @tasks.cancel_by_id nil, 42
    end
  end

  # TODO: test this behavior MORE!
  it "raises exception when cancel_by_id is called w/invalid node and task IDs are supplied" do
    assert_raises(ArgumentError) do
      @tasks.cancel_by_id "", "also_should_be_integer_id"
    end
  end

  # NOTE: unlike get_by_id, cancellation API doesn't return 404 when valid node_id and task_id
  # params don't match known nodes/running tasks, so there's no matching test for that here.

end

```

# test/client/template_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::Cluster do

  before do
    @name = "elastomer-template-test"
    @template = $client.template @name
  end

  after do
    @template.delete if @template.exists?
  end

  it "lists templates in the cluster" do
    if $client.version_support.es_version_8_plus?
      @template.create({index_patterns: ["test-elastomer*"]})
    else
      @template.create({template: "test-elastomer*"})
    end
    templates = $client.cluster.templates

    refute_empty templates, "expected to see a template"
  end

  it "creates a template" do
    refute_predicate @template, :exists?, "the template should not exist"

    if $client.version_support.es_version_8_plus?
      template_config = {index_patterns: ["test-elastomer*"]}
    else
      template_config = {template: "test-elastomer*"}
    end

    template_config.merge!({
      settings: { number_of_shards: 3 },
      mappings: mappings_wrapper("book", {
        _source: { enabled: false }
      })
    })

    @template.create(template_config)

    assert_predicate @template, :exists?, " we now have a cluster-test template"

    template = @template.get

    assert_equal [@name], template.keys

    if $client.version_support.es_version_8_plus?
      assert_equal "test-elastomer*", template[@name]["index_patterns"][0]
    else
      assert_equal "test-elastomer*", template[@name]["template"]
    end

    assert_equal "3", template[@name]["settings"]["index"]["number_of_shards"]
  end
end

```

# test/client/update_by_query_test.rb

```rb
# frozen_string_literal: true

require_relative "../test_helper"

describe ElastomerClient::Client::UpdateByQuery do
  before do
    @index = $client.index "elastomer-update-by-query-test"
    @index.delete if @index.exists?
    @docs = @index.docs("docs")
  end

  after do
    @index.delete if @index.exists?
  end

  describe "when an index with documents exists" do
    before do
      @index.create(nil)
      wait_for_index(@index.name)
    end

    it "updates by query" do
      @docs.index({ _id: 0, name: "mittens" })
      @docs.index({ _id: 1, name: "luna" })

      @index.refresh

      query = {
        query: {
          match: {
            name: "mittens"
          }
        },
        script: {
          source: "ctx._source.name = 'mittens updated'"
        }
      }

      response = @index.update_by_query(query)

      refute_nil response["took"]
      refute(response["timed_out"])
      assert_equal(1, response["batches"])
      assert_equal(1, response["total"])
      assert_equal(1, response["updated"])
      assert_empty(response["failures"])

      @index.refresh
      response = @docs.multi_get(ids: [0, 1])

      assert_equal "mittens updated", response.fetch("docs")[0]["_source"]["name"]
      assert_equal "luna", response.fetch("docs")[1]["_source"]["name"]
    end

    it "fails when internal version is 0" do
      if $client.version_support.es_version_8_plus?
        skip "Concurrency control with internal version is not supported in ES #{$client.version}"
      end
      @docs.index({_id: 0, name: "mittens"})
      # Creating a document with external version 0 also sets the internal version to 0
      # Otherwise you can't index a document with version 0.
      @docs.index({_id: 1, _version: 0, _version_type: "external", name: "mittens"})
      @index.refresh

      query = {
        query: {
          match: {
            name: "mittens"
          }
        }
      }

      assert_raises(ElastomerClient::Client::RequestError) do
        @index.update_by_query(query)
      end
    end

    it "fails when an unknown parameter is provided" do
      assert_raises(ElastomerClient::Client::IllegalArgument) do
        @index.update_by_query({}, foo: "bar")
      end
    end

    it "updates by query when routing is specified" do
      index = $client.index "elastomer-update-by-query-routing-test"
      index.delete if index.exists?
      type = "docs"
      # default number of shards in ES8 is 1, so set it to 2 shards so routing to different shards can be tested
      settings = $client.version_support.es_version_8_plus? ? { number_of_shards: 2 } : {}
      index.create({
        settings:,
        mappings: mappings_wrapper(type, {
          properties: {
            name: { type: "text", analyzer: "standard" },
          },
          _routing: { required: true }
        })
      })
      wait_for_index(@index.name)
      docs = index.docs(type)

      docs.index({ _id: 0, _routing: "cat", name: "mittens" })
      docs.index({ _id: 1, _routing: "cat", name: "luna" })
      docs.index({ _id: 2, _routing: "dog", name: "mittens" })

      query = {
        query: {
          match: {
            name: "mittens"
          }
        },
        script: {
          source: "ctx._source.name = 'mittens updated'"
        }
      }

      index.refresh
      response = index.update_by_query(query, routing: "cat")

      assert_equal(1, response["updated"])

      response = docs.multi_get({
        docs: [
          { _id: 0, routing: "cat" },
          { _id: 1, routing: "cat" },
          { _id: 2, routing: "dog" },
        ]
      })

      assert_equal "mittens updated", response.fetch("docs")[0]["_source"]["name"]
      assert_equal "luna", response.fetch("docs")[1]["_source"]["name"]
      assert_equal "mittens", response.fetch("docs")[2]["_source"]["name"]

      index.delete if index.exists?
    end
  end
end

```

# test/core_ext/time_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../../test_helper", __FILE__)
require "elastomer_client/core_ext/time"

describe "JSON conversions for Time" do
  before do
    @name  = "elastomer-time-test"
    @index = $client.index(@name)

    unless @index.exists?
      @index.create \
        settings: { "index.number_of_shards" => 1, "index.number_of_replicas" => 0 },
        mappings: mappings_wrapper("book", {
          _source: { enabled: true },
          properties: {
            title: { type: "keyword" },
            created_at: { type: "date" }
          }
        }, !$client.version_support.es_version_8_plus?)

      wait_for_index(@name)
    end

    @docs = @index.docs
  end

  after do
    @index.delete if @index.exists?
  end

  it "generates ISO8601 formatted time strings" do
    time = Time.utc(2013, 5, 3, 10, 1, 31)

    assert_equal '"2013-05-03T10:01:31.000Z"', MultiJson.encode(time)
  end

  it "indexes time fields" do
    time = Time.utc(2013, 5, 3, 10, 1, 31)
    h = @docs.index(document_wrapper("book", {title: "Book 1", created_at: time}))

    assert_created(h)

    doc = $client.version_support.es_version_8_plus? ? @docs.get(id: h["_id"]) : @docs.get(type: "book", id: h["_id"])

    assert_equal "2013-05-03T10:01:31.000Z", doc["_source"]["created_at"]
  end
end

```

# test/middleware/encode_json_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../../test_helper", __FILE__)

describe ElastomerClient::Middleware::EncodeJson do
  let(:middleware) { ElastomerClient::Middleware::EncodeJson.new(lambda { |env| env }) }

  def process(body, content_type: nil, method: :post)
    env = { body:, request_headers: Faraday::Utils::Headers.new, method: }
    env[:request_headers]["content-type"] = content_type if content_type
    middleware.call(env)
  end

  it "handles no body" do
    result = process(nil)

    assert_nil result[:body]
    assert_equal "application/json", result[:request_headers]["content-type"]

    result = process(nil, method: :get)

    assert_nil result[:body]
    assert_nil result[:request_headers]["content-type"]
  end

  it "handles empty body" do
    result = process("")

    assert_empty result[:body]
    assert_equal "application/json", result[:request_headers]["content-type"]

    result = process("", method: :get)

    assert_empty result[:body]
    assert_nil result[:request_headers]["content-type"]
  end

  it "handles string body" do
    result = process('{"a":1}')

    assert_equal '{"a":1}', result[:body]
    assert_equal "application/json", result[:request_headers]["content-type"]
  end

  it "handles object body" do
    result = process({a: 1})

    assert_equal '{"a":1}', result[:body]
    assert_equal "application/json", result[:request_headers]["content-type"]
  end

  it "handles empty object body" do
    result = process({})

    assert_equal "{}", result[:body]
    assert_equal "application/json", result[:request_headers]["content-type"]
  end

  it "handles object body with json type" do
    result = process({a: 1}, content_type: "application/json; charset=utf-8")

    assert_equal '{"a":1}', result[:body]
    assert_equal "application/json; charset=utf-8", result[:request_headers]["content-type"]
  end

  it "handles object body with incompatible type" do
    result = process({a: 1}, content_type: "application/xml; charset=utf-8")

    assert_equal({a: 1}, result[:body])
    assert_equal "application/xml; charset=utf-8", result[:request_headers]["content-type"]
  end
end

```

# test/middleware/opaque_id_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../../test_helper", __FILE__)

describe ElastomerClient::Middleware::OpaqueId do

  before do
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.get("/_cluster/health") { |env|
        [200,

          { "X-Opaque-Id"    => env[:request_headers]["X-Opaque-Id"],
            "Content-Type"   => "application/json; charset=UTF-8",
            "Content-Length" => "49" },

          %q[{"cluster_name":"elasticsearch","status":"green"}]
]
      }

      stub.get("/_cluster/state") { |env|
        [200, {"X-Opaque-Id" => "00000000-0000-0000-0000-000000000000"}, %q[{"foo":"bar"}]]
      }
    end

    opts = $client_params.merge \
        opaque_id: true,
        adapter: [:test, stubs]

    @client = ElastomerClient::Client.new(**opts)
    @client.instance_variable_set(:@version, "5.6.4")
  end

  it 'generates an "X-Opaque-Id" header' do
    health = @client.cluster.health

    assert_equal({"cluster_name" => "elasticsearch", "status" => "green"}, health)
  end

  it "raises an exception on conflicting headers" do
    assert_raises(ElastomerClient::Client::OpaqueIdError) { @client.cluster.state }
  end

  it "generates a UUID per call" do
    opaque_id = ElastomerClient::Middleware::OpaqueId.new

    uuid1 = opaque_id.generate_uuid
    uuid2 = opaque_id.generate_uuid

    refute_equal uuid1, uuid2, "UUIDs should be unique"
  end

  it "generates a UUID per thread" do
    opaque_id = ElastomerClient::Middleware::OpaqueId.new
    uuids = []
    threads = []

    3.times do
      threads << Thread.new { uuids << opaque_id.generate_uuid }
    end
    threads.each { |t| t.join }

    assert_equal 3, uuids.length, "expecting 3 UUIDs to be generated"

    # each UUID has 16 random characters as the base ID
    uuids.each { |uuid| assert_match(%r/\A[a-zA-Z0-9_-]{16}0{8}\z/, uuid) }

    bases = uuids.map { |uuid| uuid[0, 16] }

    assert_equal 3, bases.uniq.length, "each thread did not get a unique base ID"
  end
end

```

# test/middleware/parse_json_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../../test_helper", __FILE__)

describe ElastomerClient::Middleware::ParseJson do
  let(:middleware) { ElastomerClient::Middleware::ParseJson.new(lambda { |env| Faraday::Response.new(env) }) }
  let(:headers) { Hash.new }

  def process(body, content_type = nil)
    env = { body:, response_headers: Faraday::Utils::Headers.new(headers) }
    env[:response_headers]["content-type"] = content_type if content_type
    middleware.call(env)
  end

  it "doesn't change nil body" do
    response = process(nil)

    assert_nil response.body
  end

  it "nullifies empty body" do
    response = process("")

    assert_nil response.body
  end

  it "nullifies blank body" do
    response = process(" ")

    assert_nil response.body
  end

  it "parses json body with empty type" do
    response = process('{"a":1}')

    assert_equal({"a" => 1}, response.body)
  end

  it "parses json body of correct type" do
    response = process('{"a":1}', "application/json; charset=utf-8")

    assert_equal({"a" => 1}, response.body)
  end

  it "ignores json body if incorrect type" do
    response = process('{"a":1}', "application/xml; charset=utf-8")

    assert_equal('{"a":1}', response.body)
  end

  it "chokes on invalid json" do
    assert_raises(Faraday::ParsingError) { process "{!"      }
    assert_raises(Faraday::ParsingError) { process "invalid" }

    # surprisingly these are all valid according to MultiJson
    #
    # assert_raises(Faraday::ParsingError) { process '"a"'  }
    # assert_raises(Faraday::ParsingError) { process 'true' }
    # assert_raises(Faraday::ParsingError) { process 'null' }
    # assert_raises(Faraday::ParsingError) { process '1'    }
  end
end

```

# test/mock_response.rb

```rb
# frozen_string_literal: true

module ElastomerClient
  module Middleware
    class MockResponse < Faraday::Middleware
      def initialize(app, &block)
        super(app)
        @response_block = block
      end

      def call(env)
        env.clear_body if env.needs_body?

        env.status = 200
        env.response_headers = ::Faraday::Utils::Headers.new
        env.response_headers["Fake"] = "yes"
        env.response = ::Faraday::Response.new

        @response_block&.call(env)

        env.response.finish(env) unless env.parallel?

        env.response
      end
    end
  end
end

Faraday::Request.register_middleware \
  mock_response: ElastomerClient::Middleware::MockResponse

```

# test/notifications_test.rb

```rb
# frozen_string_literal: true

require File.expand_path("../test_helper", __FILE__)
require "elastomer_client/notifications"

describe ElastomerClient::Notifications do
  before do
    @name = "elastomer-notifications-test"
    @index = $client.index @name
    @index.delete if @index.exists?
    @events = []
    @subscriber = ActiveSupport::Notifications.subscribe do |*args|
      @events << ActiveSupport::Notifications::Event.new(*args)
    end
  end

  after do
    ActiveSupport::Notifications.unsubscribe(@subscriber)
    @index.delete if @index.exists?
  end

  it "instruments timeouts" do
    $client.stub :connection, lambda { raise Faraday::TimeoutError } do
      assert_raises(ElastomerClient::Client::TimeoutError) { $client.info }
      event = @events.detect { |e| e.payload[:action] == "cluster.info" }
      exception = event.payload[:exception]

      assert_equal "ElastomerClient::Client::TimeoutError", exception[0]
      assert_match "timeout", exception[1]
    end
  end

  it "instruments cluster actions" do
    $client.ping; assert_action_event("cluster.ping")
    $client.info; assert_action_event("cluster.info")
  end

  it "instruments node actions" do
    nodes = $client.nodes
    nodes.info; assert_action_event("nodes.info")
    nodes.stats; assert_action_event("nodes.stats")
    nodes.hot_threads; assert_action_event("nodes.hot_threads")
  end

  it "instruments index actions" do
    @index.exists?; assert_action_event("index.exists")
    @index.create(default_index_settings)

    assert_action_event("index.create")
    wait_for_index(@index.name)

    @index.get_settings; assert_action_event("index.get_settings")
    @index.update_settings(number_of_replicas: 0)

    assert_action_event("index.get_settings")
    wait_for_index(@index.name)

    @index.close; assert_action_event("index.close")
    @index.open; assert_action_event("index.open")
    @index.delete; assert_action_event("index.delete")
  end

  it "includes the response body in the payload" do
    @index.create(default_index_settings)
    event = @events.detect { |e| e.payload[:action] == "index.create" }

    assert event.payload[:response_body]
  end

  it "includes the request body in the payload" do
    @index.create(default_index_settings)
    event = @events.detect { |e| e.payload[:action] == "index.create" }

    payload = event.payload

    assert payload[:response_body]
    assert payload[:request_body]
    assert_same payload[:body], payload[:request_body]
  end

  def assert_action_event(action)
    assert @events.detect { |e| e.payload[:action] == action }, "expected #{action} event"
  end

  def stub_client(method, url, status = 200, body = '{"acknowledged":true}')
    stubs = Faraday::Adapter::Test::Stubs.new do |stub|
      stub.send(method, url) { |env| [status, {}, body] }
    end
    ElastomerClient::Client.new($client_params.merge(opaque_id: false, adapter: [:test, stubs]))
  end
end

```

# test/test_helper.rb

```rb
# frozen_string_literal: true

require "rubygems" unless defined? Gem
require "bundler"
Bundler.require(:default, :development)

require "webmock/minitest"
WebMock.allow_net_connect!

require "securerandom"

if ENV["COVERAGE"] == "true"
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
    add_filter "/vendor/"
  end
end

require "minitest/spec"
require "minitest/autorun"
require "minitest/focus"

# used in a couple test files, makes them available for all
require "active_support/core_ext/enumerable"
require "active_support/core_ext/hash"

# push the lib folder onto the load path
$LOAD_PATH.unshift "lib"
require "elastomer_client/client"

# we are going to use the same client instance everywhere!
# the client should always be stateless
$client_params = {
  port: ENV.fetch("ES_PORT", 9200),
  read_timeout: 10,
  open_timeout: 1,
  opaque_id: false,
  strict_params: true,
  compress_body: true
}
$client = ElastomerClient::Client.new(**$client_params)

# ensure we have an Elasticsearch server to test with
raise "No server available at #{$client.url}" unless $client.available?

puts "Elasticsearch version is #{$client.version}"

# remove any lingering test indices from the cluster
Minitest.after_run do
  $client.cluster.indices.keys.each do |name|
    next unless name =~ /^elastomer-/i
    $client.index(name).delete
  end

  $client.cluster.templates.keys.each do |name|
    next unless name =~ /^elastomer-/i
    $client.template(name).delete
  end
end

# add custom assertions
require File.expand_path("../assertions", __FILE__)

# require 'elastomer_client/notifications'
# require 'pp'

# ActiveSupport::Notifications.subscribe('request.client.elastomer') do |name, start_time, end_time, transaction_id, payload|
#   $stdout.puts '-'*100
#   #$stdout.puts "-- #{payload[:action].inspect}"
#   pp payload #if payload[:action].nil?
# end

# Wait for an index to be created. Since index creation requests return
# before the index is actually ready to receive documents, one needs to wait
# until the cluster status recovers before proceeding.
#
#   name   - The index name to wait for
#   status - The status to wait for. Defaults to yellow. Yellow is the
#            preferred status for tests, because it waits for at least one
#            shard to be active, but doesn't wait for all replicas. Single
#            node clusters will never achieve green status with the default
#            setting of 1 replica.
#
# Returns the cluster health response.
# Raises ElastomerClient::Client::TimeoutError if requested status is not achieved
# within 5 seconds.
def wait_for_index(name, status = "yellow")
  $client.cluster.health(
    index: name,
    wait_for_status: status,
    timeout: "5s"
  )
end

def default_index_settings
  {settings: {index: {number_of_shards: 1, number_of_replicas: 0}}}
end

def run_snapshot_tests?
  unless defined? $run_snapshot_tests
    begin
      create_repo("elastomer-client-snapshot-test")
      $run_snapshot_tests = true
    rescue ElastomerClient::Client::Error
      puts "Could not create a snapshot repo. Snapshot tests will be disabled."
      puts "To enable snapshot tests, add a path.repo setting to your elasticsearch.yml file."
      $run_snapshot_tests = false
    ensure
      delete_repo("elastomer-client-snapshot-test")
    end
  end
  $run_snapshot_tests
end

def create_repo(name, settings = {})
  location = File.join(*[ENV["SNAPSHOT_DIR"], name].compact)
  default_settings = {type: "fs", settings: {location:}}
  $client.repository(name).create(default_settings.merge(settings))
end

def delete_repo(name)
  repo = $client.repository(name)
  repo.delete if repo.exists?
end

def delete_repo_snapshots(name)
  repo = $client.repository(name)
  if repo.exists?
    response = repo.snapshots.get
    response["snapshots"].each do |snapshot_info|
      repo.snapshot(snapshot_info["snapshot"]).delete
    end
  end
end

def with_tmp_repo(name = SecureRandom.uuid, &block)
  begin
    create_repo(name)
    yield $client.repository(name)
  ensure
    delete_repo_snapshots(name)
    delete_repo(name)
  end
end

def create_snapshot(repo, name = SecureRandom.uuid)
  repo.snapshot(name).create({}, wait_for_completion: true)
end

def with_tmp_snapshot(name = SecureRandom.uuid, &block)
  with_tmp_repo do |repo|
    create_snapshot(repo, name)
    yield repo.snapshot(name), repo
  end
end

# Just some busy work in the background for tasks API to detect in test cases
#
# Returns the thread and index references so caller can join the thread and delete
# the index after the checks are performed
def populate_background_index!(name)
  # make an index with a new client (in this thread, to avoid query check race after)
  name.freeze
  index = $client.dup.index(name)
  docs = index.docs("widget")

  # do some busy work in background thread to generate bulk-indexing tasks we
  # can query at the caller. return the thread ref so caller can join on it
  Thread.new do
    100.times.each do |i|
      docs.bulk do |d|
        (1..500).each do |j|
          d.index \
            foo: "foo_#{i}_#{j}",
            bar: "bar_#{i}_#{j}",
            baz: "baz_#{i}_#{j}"
        end
      end
      index.refresh
    end
  end
end

# when populate_background_index! is running, this query returns healthcheck tasks
# that are long-running enough to be queried again for verification in test cases
def query_long_running_tasks
  Kernel.sleep(0.01)
  target_tasks = []
  100.times.each do
    target_tasks = @tasks.get["nodes"]
      .map { |k, v| v["tasks"] }
      .flatten.map { |ts| ts.select { |k, v| /bulk/ =~ v["action"] } }
      .flatten.reject { |t| t.empty? }
    break if target_tasks.size > 0
  end

  target_tasks
end

# The methods below are to support intention-revealing names about version
# differences in the tests. If necessary for general operation they can be moved
# into ElastomerClient::VersionSupport.

# COMPATIBILITY
# ES8 drops mapping types, so don't wrap with a mapping type for ES8+
def mappings_wrapper(type, body, disable_all = false)
  if $client.version_support.es_version_8_plus?
    body
  else
    mapping = {
      _default_: {
        dynamic: "strict"
      }
    }
    mapping[type] = body
    if disable_all then mapping[type]["_all"] = { "enabled": false } end
    mapping
  end
end

# COMPATIBILITY
# ES8 drops mapping types, so append type to the document only if ES version < 8
def document_wrapper(type, body)
  if $client.version_support.es_version_8_plus?
    body
  else
    body.merge({_type: type})
  end
end

```

# test/version_support_test.rb

```rb
# frozen_string_literal: true

require_relative "test_helper"

describe ElastomerClient::VersionSupport do
  describe "supported versions" do
    it "allows 5.0.0 to 8.x" do
      five_series = ["5.0.0", "5.0.9", "5.1.0", "5.9.0", "5.99.100"]
      eight_series = ["8.0.0", "8.0.9", "8.1.0", "8.9.0", "8.99.100"]

      five_series.each do |version|
        assert ElastomerClient::VersionSupport.new(version)
      end

      eight_series.each do |version|
        assert_predicate ElastomerClient::VersionSupport.new(version), :es_version_8_plus?
      end
    end
  end

  describe "unsupported versions" do
    it "blow up" do
      too_low = ["0.90", "1.0.1", "2.0.0", "2.2.0"]
      too_high = ["9.0.0"]

      (too_low + too_high).each do |version|
        exception = assert_raises(ArgumentError, "expected #{version} to not be supported") do
          ElastomerClient::VersionSupport.new(version)
        end

        assert_match version, exception.message
        assert_match "is not supported", exception.message
      end
    end
  end
end

```

