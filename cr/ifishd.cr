require "openssl/cipher"
require "io/console"
require "base64"

def dsv(k, e)
  bf = OpenSSL::Cipher.new("blowfish")
  bf.decrypt
  bf.iv = e[0..7]
  bf.key = k[16..31]
  p = String.new(bf.update(e[8..])) + String.new(bf.final)
  (s2v(k[0..15], p) == e[0..7]) ? return p : return false
end

def s2v(k, p)
  d = cmac(k, "\x00\x00\x00\x00\x00\x00\x00\x00")
  t = String::Builder.new
  if p.size >= 8
    p[(p.size - d.size)...(p.size)].bytes.zip(d).map { |a, b| t << (a ^ b).chr }
  else
    p += "\x01"
    p += "\x00"*(8 - p.size)
    p.bytes.zip(d.map(&.<<(1).^(27))).map { |a, b| t << (a ^ b).chr }
  end
  return cmac(k, t.to_s)
end

def cmac(k, s)
  bf = OpenSSL::Cipher.new("bf-ecb")
  bf.encrypt
  r = Slice.new(8, 0.to_u8)
  m = s.bytes.map(&.to_u8)
  bf.iv = "\x00\x00\x00\x00\x00\x00\x00\x00"
  bf.key = k
  l = bf.update "\x00\x00\x00\x00\x00\x00\x00\x00"
  k1 = l.map(&.<<(1).^(0x27))
  k2 = k1.map(&.<<(1).^(0x27))
  while s = m.shift(8)
    if s.size != 8
      s << 1
      (8 - s.size).times { s << 0 }
      (0..7).each do |i|
        r[i] = (s[i] ^ r[i] ^ k2[i])
      end
      return bf.update(r)
    elsif m.empty?
      (0..7).each do |i|
        r[i] = (s[i] ^ r[i] ^ k1[i])
      end
      return bf.update(r)
    end
    (0..7).each do |i|
      r[i] = (s[i] ^ r[i])
    end
    r = bf.update(r)
  end
  return bf.update(r)
end

STDERR.print "Key:"
k = STDIN.noecho &.gets.try &.strip
k ? STDERR.puts nil : exit 0
puts dsv (cmac("\x00"*16,k).to_a+cmac("\x20"*16,k).to_a+cmac("\x40"*16,k).to_a+cmac("\x60"*16,k).to_a+cmac("\x80"*16,k).to_a).to_s, Base64.decode ARGF.gets_to_end
