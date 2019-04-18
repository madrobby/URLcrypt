require 'test_helper'

class TestURLcrypt < TestClass
  def test_empty_string
    assert_encode_and_decode('', '')
  end

  def test_encode
    assert_encode_and_decode(
      '111gc86f4nxw5zj1b3qmhpb14n5h25l4m7111',
      "\0\0awesome \n ü string\0\0")
  end

  def test_invalid_encoding
    assert_decoding('ZZZZZ', '')
  end

  def test_arbitrary_byte_strings
    0.step(1500,17) do |n|
      original = (0..n).map{rand(256).chr}.join
      encoded = URLcrypt::encode(original)
      assert_decoding(encoded, original)
    end
  end
  
  def test_encryption
    # pack() converts this secret into a byte array
    secret = ['d25883a27b9a639da85ea7e159b661218799c9efa63069fac13a6778c954fb6d'].pack('H*')
    URLcrypt::key = secret

    assert_equal  OpenSSL::Cipher.new('aes-256-cbc').key_len, secret.bytesize

    original  = "hello world!"
    encrypted = URLcrypt::encrypt(original)
    assert_equal(URLcrypt::decrypt(encrypted), original)
  end

  def test_decrypt_error
    error = assert_raises(URLcrypt::DecryptError) do
      ::URLcrypt::decrypt("just some plaintext")
    end
    assert_equal error.message, "not a valid string to decrypt"
  end
end
