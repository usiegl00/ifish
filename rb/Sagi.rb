require "io/console"
require "openssl"
def siv(k,p,s=[])
  bf = OpenSSL::Cipher.new("blowfish").encrypt
  k1 = k[0..15]
  k2 = k[16..31]
  t = s2v(k1,p,s)
  bf.iv = t
  bf.key = k2
  return t + bf.update(p) + bf.final
end
def s2v(k,p,s=[])
  d = cmc(k,"\x00"*8).unpack("B*")[0].to_i(2)
  t = ""
  s.each do |l|
    d = ((d<<1)^27)^cmc(k,l).unpack("B*")[0].to_i(2)
  end
  if p.size >= 8
    p[(p.size-d.size)...(p.size)].bytes.zip(d.digits).map{|a,b|t<<(a^b).chr}
  else
    t = ""
    p << "\x01"
    p << "\x00"*(8-p.size)
    p.bytes.zip(((d<<1)^27).digits).map{|a,b|t<<(a^b).chr}
  end
  return cmc(k,t)
end
def cmc(k,s)
  bf = OpenSSL::Cipher.new("blowfish").encrypt
  r = "\x00"*8
  m = s.chars
  s.clear
  bf.iv = "\x00"*8
  bf.key = k
  l = bf.update("\x00"*8).unpack("B*")[0].to_i(2)
  if l[1] == 0
    k1 = l<<1
  else
    k1 = (l<<1)^27
  end
  if k1[1] == 0
    k2 = k1<<1
  else
    k2 = (k1<<1)^27
  end
  bf.reset
  while s << m.shift(8).join
    if s.size != 8
      s << 1
      s << "\x00"*(8-s.size)
      (0..7).each do |i|
        r[i] = (s[i].ord^r[i].ord^k2.to_s.bytes[i]).chr
      end
      return bf.update(r)
    elsif m.empty?
      (0..7).each do |i|
        r[i] = (s[i].ord^r[i].ord^k1.to_s.bytes[i]).chr
      end
      return bf.update(r)
    end
    (0..7).each do |i|
      r[i] = (s[i].ord^r[i].ord).chr
    end
    s.clear
    r = bf.update(r)
  end
  return r
end
def tree(s)
  t = ""
  s << "\x01"
  l = s.length.divmod(8)
  s << "\x00" * (8 - l[1])
  s << "\x00" * 8 if l[0].even?
  s = s.scan(/.{8}/m)
  while s.size > 1
    s << s[-1] if s.size % 2 != 0
    r = []
    s.each_slice(2) do |h|
      t = hirose(h[0], h[1])
      l.clear
      t[0..7].bytes.zip(t[8..15].bytes).map{|a,b|l<<(a^b).chr}
      r << l.join
    end
    s = r
  end
  return t
end
def hirose(iv, m)
  b = OpenSSL::Cipher.new("blowfish").encrypt
  f = OpenSSL::Cipher.new("blowfish").encrypt
  g = ""
  h = ""
  b.iv = iv
  f.iv = iv
  b.key = iv + m
  f.key = iv + m
  iv.bytes.map{|b|g<<(b^1).chr}
  b.update(g).bytes.zip(g.bytes).map{|a,b|h<<(a^b).chr}
  g.clear
  f.update(iv).bytes.zip(iv.bytes).map{|a,b|g<<(a^b).chr}
  return h + g
end
puts [siv(tree(IO::console.getpass("KEY:")).unpack("H*")[0], ARGF.read.strip)].pack("m")
