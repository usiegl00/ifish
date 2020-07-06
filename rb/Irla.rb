require "openssl"
def hr(s)
  b = OpenSSL::Cipher.new("blowfish").encrypt
  f = OpenSSL::Cipher.new("blowfish").encrypt
  h = "\x00" * 8
  g = "\x00" * 8
  c = "\x01" * 8
  s << "\x01"
  s << "\x00" * (8 - s.length % 8)
  s = s.chars.each_slice(8).map(&:join)
  while !s.empty?
    b.reset
    f.reset
    x = s.pop
    b.iv = x
    f.iv = x
    x << h
    b.key = x
    f.key = x
    m = ""
    g.bytes.zip(c.bytes).map{|a,b|m<<(a^b).chr}
    h = ""
    b.update(m).bytes.zip(g.bytes).map{|a,b|h<<(a^b).chr}
    x = ""
    f.update(g).bytes.zip(g.bytes).map{|a,b|x<<(a^b).chr}
    g = x
  end
  return h + g
end
def hirose(iv, m)
  b = OpenSSL::Cipher.new("blowfish").encrypt
  f = OpenSSL::Cipher.new("blowfish").encrypt
  g = ""
  h = ""
  c = "\x01" * 8
  b.iv = iv
  f.iv = iv
  b.key = iv + m
  f.key = iv + m
  iv.bytes.zip(c.bytes).map{|a,b|g<<(a^b).chr}
  b.update(g).bytes.zip(g.bytes).map{|a,b|h<<(a^b).chr}
  g.clear
  f.update(iv).bytes.zip(iv.bytes).map{|a,b|g<<(a^b).chr}
  return h + g
end
puts hr(ARGF.read.force_encoding("Binary")).unpack("H*")[0]
