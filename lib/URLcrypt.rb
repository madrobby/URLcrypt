require 'openssl'
require 'base64'

module URLcrypt
  # avoid vowels to not generate four-letter words, etc.
  # this is important because those words can trigger spam 
  # filters when URLs are used in emails
  TABLE = "1bcd2fgh3jklmn4pqrstAvwxyz567890".freeze

  def self.encoding_engine=(val)
    @encoding_engine = val
  end

  def self.encoding_engine
    @encoding_engine || Base32Encoder
  end

  def self.key=(key)
    @key = key
  end

  class Chunk
    def initialize(bytes)
      @bytes = bytes
      @encoder = URLcrypt.encoding_engine
    end

    def decode
      @encoder.new(@bytes).decode
    end
    
    def encode
      @encoder.new(@bytes).encode
    end
  end

  class Base64Encoder
    def initialize(bytes)
      @bytes = bytes
    end

    def encode
      Base64.encode64(@bytes).gsub("\n", "")
    end

    def decode
      Base64.decode64(@bytes)
    end
  end

  class Base64EscapedEncoder
    def initialize(bytes)
      @bytes = bytes
    end

    def encode
      CGI.escape Base64Encoder.new(@bytes).encode
    end

    def decode
      Base64Encoder.new(CGI.unescape(@bytes)).decode
    end
  end

  class Base32Encoder

    def initialize(bytes)
      @bytes = bytes
    end

    def decode
      bytes = @bytes.take_while {|c| c != 61} # strip padding
      bytes = bytes.find_all{|b| !TABLE.index(b.chr).nil? } # remove invalid characters
      n = (bytes.length * 5.0 / 8.0).floor
      p = bytes.length < 8 ? 5 - (n * 8) % 5 : 0
      c = bytes.inject(0) {|m,o| (m << 5) + TABLE.index(o.chr)} >> p
      (0..n-1).to_a.reverse.collect {|i| ((c >> i * 8) & 0xff).chr}
    end

    def encode
      n = (@bytes.length * 8.0 / 5.0).ceil
      p = n < 8 ? 5 - (@bytes.length * 8) % 5 : 0
      c = @bytes.inject(0) {|m,o| (m << 8) + o} << p
      [(0..n-1).to_a.reverse.collect {|i| TABLE[(c >> i * 5) & 0x1f].chr},
       ("=" * (8-n))] # TODO: remove '=' padding generation
    end
    
  end

  def self.chunks(str, size)
    result = []
    bytes = str.bytes
    while bytes.any? do
      result << Chunk.new(bytes.take(size))
      bytes = bytes.drop(size)
    end
    result
  end

  # strip '=' padding, because we don't need it
  def self.encode(data)
    chunks(data, 5).collect(&:encode).flatten.join.tr('=','')
  end

  def self.decode(data)
    chunks(data, 8).collect(&:decode).flatten.join
  end
  
  def self.decrypt(data)
    iv, encrypted = data.split('Z').map{|part| decode(part)}
    fail DecryptError, "not a valid string to decrypt" unless iv && encrypted
    decrypter = cipher(:decrypt)
    decrypter.iv = iv
    decrypter.update(encrypted) + decrypter.final 
  end
    
  def self.encrypt(data)
    crypter = cipher(:encrypt)
    crypter.iv = iv = crypter.random_iv
    "#{encode(iv)}Z#{encode(crypter.update(data) + crypter.final)}"
  end
  
  private 
    
    def self.cipher(mode)
      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.send(mode)
      cipher.key = @key
      cipher
    end

  class DecryptError < ::ArgumentError; end
end
