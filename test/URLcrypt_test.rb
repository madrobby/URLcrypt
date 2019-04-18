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
    # this key was generated via rake secret in a rails app, the pack() converts it into a byte array
    URLcrypt::key =
['d25883a27b9a639da85ea7e159b661218799c9efa63069fac13a6778c954fb6d721968887a19bdb01af8f59eb5a90d256bd9903355c20b0b4b39bf4048b9b17b'].pack('H*')
    
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
