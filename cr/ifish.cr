require "crypto/blowfish"

def hirose(s)
  b = Crypto::Blowfish.new(128)
  h = [0, 0] of UInt32
  g = [0, 0] of UInt32
  s << 128
  l = s.size % 2
  (8 - l).times { s << 0 } unless l == 0
  s.each_slice(8) do |m|
    b.expand_key(h + m)
    r = g.map(&.^(255_u8))
    g = (b.encrypt_pair g[0], g[1]).zip(g).map { |a, b| a ^ b }
    h = (b.encrypt_pair r[0], r[1]).zip(r).map { |a, b| a ^ b }
  end
  return ias h + g
end
@[AlwaysInline]
def ias(ia)
  s = IO::Memory.new
  ia.each do |i|
    s.write_bytes i
  end
  return s.to_slice
end

puts hirose(ARGF.gets_to_end.bytes).hexstring
