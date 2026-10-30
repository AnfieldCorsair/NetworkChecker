using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetworkChecker.Core.Capture;

/// <summary>Ограниченный просмотр пакетных файлов, без открытия устройств и сетевой активности.</summary>
public static class CaptureReader
{
    public const int MaxFileBytes = 32 * 1024 * 1024;
    public const int MaxPackets = 2000;
    private const int MaxFrameBytes = 1024 * 1024;

    public static CaptureDocument Read(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length > MaxFileBytes) throw new InvalidDataException("Файл больше 32 МиБ.");
        if (data.Length < 4) throw new InvalidDataException("Файл слишком короткий.");
        return BinaryPrimitives.ReadUInt32LittleEndian(data) == 0x0a0d0d0a ? ReadPcapNg(data) : ReadPcap(data);
    }

    private static CaptureDocument ReadPcap(byte[] data)
    {
        if (data.Length < 24) throw new InvalidDataException("Неполный заголовок PCAP.");
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        var little = magic is 0xa1b2c3d4 or 0xa1b23c4d;
        if (!little && magic is not (0xd4c3b2a1 or 0x4d3cb2a1)) throw new InvalidDataException("Неизвестный формат файла.");
        if (U16(data, 4, little) != 2 || U16(data, 6, little) != 4) throw new InvalidDataException("Неподдерживаемая версия PCAP.");
        var network = U32(data, 20, little) & 0xffff;
        var rows = new List<CapturePacket>();
        var pos = 24;
        while (pos < data.Length && rows.Count < MaxPackets)
        {
            if (data.Length - pos < 16) throw new InvalidDataException("Неполный заголовок пакета PCAP.");
            var size = U32(data, pos + 8, little);
            var original = U32(data, pos + 12, little);
            pos += 16;
            if (size > MaxFrameBytes || size > (uint)(data.Length - pos) || size > original)
                throw new InvalidDataException("Некорректная длина пакета PCAP.");
            rows.Add(Describe(data.AsSpan(pos, (int)size), network, original));
            pos += (int)size;
        }
        return new CaptureDocument("PCAP", rows, pos < data.Length, 0);
    }

    private static CaptureDocument ReadPcapNg(byte[] data)
    {
        var rows = new List<CapturePacket>();
        var links = new List<ushort>();
        var pos = 0;
        var little = true;
        var haveSection = false;
        var skipped = 0;
        while (pos < data.Length && rows.Count < MaxPackets)
        {
            if (data.Length - pos < 12) throw new InvalidDataException("Неполный блок PCAPNG.");
            var section = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos)) == 0x0a0d0d0a;
            if (section)
            {
                var bom = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos + 8));
                little = bom == 0x1a2b3c4d;
                if (!little && bom != 0x4d3c2b1a) throw new InvalidDataException("Неизвестный порядок байтов PCAPNG.");
                links.Clear();
                haveSection = true;
            }
            if (!haveSection) throw new InvalidDataException("Нет заголовка секции PCAPNG.");
            var type = U32(data, pos, little);
            var length = U32(data, pos + 4, little);
            if (length < 12 || length % 4 != 0 || length > (uint)(data.Length - pos) ||
                U32(data, pos + (int)length - 4, little) != length)
                throw new InvalidDataException("Некорректная длина блока PCAPNG.");
            if (section && (length < 28 || U16(data, pos + 12, little) != 1))
                throw new InvalidDataException("Неподдерживаемый заголовок секции PCAPNG.");
            if (type == 1)
            {
                if (length < 20) throw new InvalidDataException("Неполное описание интерфейса PCAPNG.");
                links.Add(U16(data, pos + 8, little));
            }
            else if (type == 6)
            {
                if (length < 32) throw new InvalidDataException("Неполный пакет PCAPNG.");
                var iface = U32(data, pos + 8, little);
                var size = U32(data, pos + 20, little);
                var original = U32(data, pos + 24, little);
                if (iface >= links.Count || size > MaxFrameBytes || size > original || ((size + 3) & ~3u) > length - 32)
                    throw new InvalidDataException("Некорректный пакет PCAPNG.");
                rows.Add(Describe(data.AsSpan(pos + 28, (int)size), links[(int)iface], original));
            }
            else if (!section && type != 1) skipped++;
            pos += (int)length;
        }
        return new CaptureDocument("PCAPNG", rows, pos < data.Length, skipped);
    }

    private static ushort U16(byte[] data, int pos, bool little) => little
        ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(pos)) : BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos));
    private static uint U32(byte[] data, int pos, bool little) => little
        ? BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(pos)) : BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));

    private static CapturePacket Describe(ReadOnlySpan<byte> frame, uint link, uint original)
    {
        var protocol = $"LinkType {link}";
        var source = "—";
        var destination = "—";
        if (link == 1 && frame.Length >= 14)
        {
            var offset = 14;
            var ether = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
            // Один или несколько VLAN-тегов.
            while (ether is 0x8100 or 0x88a8 && frame.Length >= offset + 4)
            {
                ether = BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + 2)..]);
                offset += 4;
            }
            if (ether == 0x0800 && frame.Length >= offset + 20 && (frame[offset] >> 4) == 4)
            {
                var hlen = (frame[offset] & 0x0f) * 4;
                if (hlen >= 20 && frame.Length >= offset + hlen)
                {
                    source = new IPAddress(frame.Slice(offset + 12, 4)).ToString();
                    destination = new IPAddress(frame.Slice(offset + 16, 4)).ToString();
                    var ipProtocol = frame[offset + 9];
                    protocol = ipProtocol switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", _ => $"IPv4/{ipProtocol}" };
                    var fragment = BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + 6)..]);
                    if ((fragment & 0x1fff) == 0 && ipProtocol is 6 or 17 && frame.Length >= offset + hlen + 4)
                    {
                        source += ":" + BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + hlen)..]);
                        destination += ":" + BinaryPrimitives.ReadUInt16BigEndian(frame[(offset + hlen + 2)..]);
                    }
                }
            }
            else if (ether == 0x86dd && frame.Length >= offset + 40 && (frame[offset] >> 4) == 6)
            {
                source = new IPAddress(frame.Slice(offset + 8, 16)).ToString();
                destination = new IPAddress(frame.Slice(offset + 24, 16)).ToString();
                // Расширения IPv6 не разбираются и не приписываются TCP/UDP ошибочно.
                protocol = frame[offset + 6] switch { 6 => "TCP/IPv6", 17 => "UDP/IPv6", 58 => "ICMPv6", _ => "IPv6" };
            }
            else protocol = $"EtherType 0x{ether:X4}";
        }
        var shown = frame[..Math.Min(frame.Length, 256)];
        var hex = new StringBuilder();
        for (var i = 0; i < shown.Length; i++)
        {
            if (i > 0) hex.Append(i % 16 == 0 ? '\n' : ' ');
            hex.Append(shown[i].ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
        }
        if (frame.Length > shown.Length) hex.Append("\n…");
        return new CapturePacket(protocol, source, destination, frame.Length, original, hex.ToString());
    }
}

public sealed record CaptureDocument(string Format, IReadOnlyList<CapturePacket> Packets, bool Limited, int SkippedBlocks);
public sealed record CapturePacket(string Protocol, string Source, string Destination, int CapturedBytes, uint OriginalBytes, string HexPreview);
