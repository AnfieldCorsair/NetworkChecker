using System.Buffers.Binary;
using NetworkChecker.Core.Capture;
using Xunit;

namespace NetworkChecker.Core.Tests;

public class CaptureReaderTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Pcap_reads_both_byte_orders_and_ipv4_udp(bool little)
    {
        var document = CaptureReader.Read(Pcap(little));
        var p = Assert.Single(document.Packets);
        Assert.Equal("UDP", p.Protocol);
        Assert.Equal("192.0.2.1:1234", p.Source);
        Assert.Equal("198.51.100.2:53", p.Destination);
        Assert.Contains("C0 00 02 01", p.HexPreview);
    }

    [Fact]
    public void Pcapng_reads_enhanced_packets_and_checks_block_lengths()
    {
        var packet = Ethernet();
        using var s = new MemoryStream();
        void Put(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); s.Write(b); }
        Put(0x0a0d0d0a); Put(28); Put(0x1a2b3c4d); Put(0x00000001); Put(uint.MaxValue); Put(uint.MaxValue); Put(28);
        Put(1); Put(20); Put(1); Put(65535); Put(20);
        var padded = (packet.Length + 3) & ~3;
        var length = (uint)(32 + padded);
        Put(6); Put(length); Put(0); Put(0); Put(0); Put((uint)packet.Length); Put((uint)packet.Length);
        s.Write(packet); s.Write(new byte[padded - packet.Length]); Put(length);
        var bytes = s.ToArray();
        var doc = CaptureReader.Read(bytes);
        Assert.Equal("PCAPNG", doc.Format);
        Assert.Equal("UDP", Assert.Single(doc.Packets).Protocol);
        bytes[^1] ^= 0x01;
        Assert.Throws<InvalidDataException>(() => CaptureReader.Read(bytes));
    }

    [Fact]
    public void Truncated_and_huge_inputs_are_rejected()
    {
        Assert.Throws<InvalidDataException>(() => CaptureReader.Read([1, 2]));
        var bytes = Pcap(true);
        Assert.Throws<InvalidDataException>(() => CaptureReader.Read(bytes[..^1]));
        Assert.Throws<InvalidDataException>(() => CaptureReader.Read(new byte[CaptureReader.MaxFileBytes + 1]));
    }

    [Fact]
    public void Only_first_fragment_can_have_ports()
    {
        var bytes = Pcap(true);
        bytes[24 + 16 + 14 + 7] = 1;
        var row = Assert.Single(CaptureReader.Read(bytes).Packets);
        Assert.Equal("192.0.2.1", row.Source);
        Assert.Equal("198.51.100.2", row.Destination);
    }

    [Fact]
    public void Arbitrary_input_never_causes_out_of_range_or_memory_allocation_from_lengths()
    {
        var random = new Random(123);
        for (var i = 0; i < 1000; i++)
        {
            var bytes = new byte[random.Next(4, 500)];
            random.NextBytes(bytes);
            if (i % 2 == 0) { bytes[0] = 0x0a; bytes[1] = 0x0d; bytes[2] = 0x0d; bytes[3] = 0x0a; }
            try { _ = CaptureReader.Read(bytes); }
            catch (InvalidDataException) { }
        }
    }

    private static byte[] Pcap(bool little)
    {
        var packet = Ethernet();
        using var s = new MemoryStream();
        void U32(uint x) { Span<byte> b = stackalloc byte[4]; if (little) BinaryPrimitives.WriteUInt32LittleEndian(b, x); else BinaryPrimitives.WriteUInt32BigEndian(b, x); s.Write(b); }
        void U16(ushort x) { Span<byte> b = stackalloc byte[2]; if (little) BinaryPrimitives.WriteUInt16LittleEndian(b, x); else BinaryPrimitives.WriteUInt16BigEndian(b, x); s.Write(b); }
        U32(0xa1b2c3d4); U16(2); U16(4); U32(0); U32(0); U32(65535); U32(1);
        U32(0); U32(0); U32((uint)packet.Length); U32((uint)packet.Length); s.Write(packet);
        return s.ToArray();
    }

    private static byte[] Ethernet()
    {
        var b = new byte[14 + 20 + 8];
        b[12] = 0x08; b[13] = 0; b[14] = 0x45; b[23] = 17;
        b[26] = 192; b[27] = 0; b[28] = 2; b[29] = 1;
        b[30] = 198; b[31] = 51; b[32] = 100; b[33] = 2;
        b[34] = 0x04; b[35] = 0xd2; b[36] = 0; b[37] = 53;
        return b;
    }
}
