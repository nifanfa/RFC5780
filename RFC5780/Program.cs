using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

UdpClient uc = new UdpClient(0, AddressFamily.InterNetwork);
IPEndPoint publicEndPoint = new IPEndPoint(IPAddress.Any, 0);
if (IsFullCone(uc, ref publicEndPoint))
{
    Console.WriteLine($"Full cone! Public ip end point: {publicEndPoint}");
}
else
{
    Console.WriteLine("Not full cone!");
}

static bool IsFullCone(UdpClient uc, ref IPEndPoint publicEndPoint)
{
    byte[] MessageCookie = [0x21, 0x12, 0xa4, 0x42]; //RFC5780

    IPEndPoint server = new IPEndPoint(
        Dns.GetHostEntry("stun.miwifi.com", AddressFamily.InterNetwork).AddressList.First(),
        3478);
    IPEndPoint ipe = new IPEndPoint(IPAddress.Any, 0);

    bool has_other_address = false;

    {
        Header header = new Header()
        {
            MessageType = ((ushort)1).ReverseEndianness(),
            MessageCookie = MessageCookie,
            MessageLength = 0,
        };
        uc.Send(header.ToArray(), server);
    }
    {
        byte[] buffer = uc.Receive(ref ipe);
        int offset = 0;
        int total_length = 0;
        {
            Header header = buffer.ToStructure<Header>(offset);
            header.MessageType = header.MessageLength.ReverseEndianness();
            header.MessageLength = header.MessageLength.ReverseEndianness();

            total_length = Marshal.SizeOf<Header>() + header.MessageLength;
            offset += Marshal.SizeOf<Header>();
        }
        while (offset < total_length)
        {
            Attribute att = buffer.ToStructure<Attribute>(offset);
            att.AttributeType = (AttributeType)((ushort)att.AttributeType).ReverseEndianness();
            att.AttributeLength = att.AttributeLength.ReverseEndianness();

            offset += Attribute.HeaderLength;
            switch (att.AttributeType)
            {
                case AttributeType.MAPPED_ADDRESS:
                case AttributeType.XOR_MAPPED_ADDRESS:
                case AttributeType.RESPONSE_ORIGIN:
                case AttributeType.OTHER_ADDRESS:
                    {
                        if (att.AttributeType == AttributeType.XOR_MAPPED_ADDRESS)
                        {
                            {
                                byte[] bytes = BitConverter.GetBytes(att.Port);
                                for (int i = 0; i < bytes.Length; i++)
                                {
                                    bytes[i] ^= MessageCookie[i];
                                }
                                att.Port = BitConverter.ToUInt16(bytes);
                            }
                            {
                                byte[] bytes = BitConverter.GetBytes(att.IP);
                                for (int i = 0; i < bytes.Length; i++)
                                {
                                    bytes[i] ^= MessageCookie[i];
                                }
                                att.IP = BitConverter.ToUInt32(bytes);
                            }
                        }
                        if (att.AttributeType == AttributeType.OTHER_ADDRESS)
                        {
                            has_other_address = true;
                        }
                        att.Port = att.Port.ReverseEndianness();
                        IPEndPoint result = new IPEndPoint(new IPAddress(att.IP), att.Port);
                    }
                    break;
            }
            offset += att.AttributeLength;
        }
    }
    if (has_other_address)
    {
        {
            Header header = new Header()
            {
                MessageType = ((ushort)1).ReverseEndianness(),
                MessageCookie = MessageCookie,
                MessageLength = ((ushort)(Attribute.HeaderLength + sizeof(uint))).ReverseEndianness(),
            };
            Attribute att = new Attribute()
            {
                AttributeType = (AttributeType)((ushort)AttributeType.CHANGE_REQUEST).ReverseEndianness(),
                AttributeLength = ((ushort)sizeof(uint)).ReverseEndianness(),
                ChangeRequest = (ChangeRequest)((uint)(
                    ChangeRequest.ChangeIP
                  | ChangeRequest.ChangePort
                )).ReverseEndianness()
            };
            uc.Send([.. header.ToArray(), .. att.ToArray(Attribute.HeaderLength + sizeof(uint))], server);
        }
        {
            byte[] buffer = uc.Receive(ref ipe);
            int offset = 0;
            int total_length = 0;
            {
                Header header = buffer.ToStructure<Header>(offset);
                header.MessageType = header.MessageLength.ReverseEndianness();
                header.MessageLength = header.MessageLength.ReverseEndianness();

                total_length = Marshal.SizeOf<Header>() + header.MessageLength;
                offset += Marshal.SizeOf<Header>();
            }
            while (offset < total_length)
            {
                Attribute att = buffer.ToStructure<Attribute>(offset);
                att.AttributeType = (AttributeType)((ushort)att.AttributeType).ReverseEndianness();
                att.AttributeLength = att.AttributeLength.ReverseEndianness();

                offset += Attribute.HeaderLength;
                switch (att.AttributeType)
                {
                    case AttributeType.MAPPED_ADDRESS:
                    case AttributeType.XOR_MAPPED_ADDRESS:
                    case AttributeType.RESPONSE_ORIGIN:
                    case AttributeType.OTHER_ADDRESS:
                        {
                            if (att.AttributeType == AttributeType.XOR_MAPPED_ADDRESS)
                            {
                                {
                                    byte[] bytes = BitConverter.GetBytes(att.Port);
                                    for (int i = 0; i < bytes.Length; i++)
                                    {
                                        bytes[i] ^= MessageCookie[i];
                                    }
                                    att.Port = BitConverter.ToUInt16(bytes);
                                }
                                {
                                    byte[] bytes = BitConverter.GetBytes(att.IP);
                                    for (int i = 0; i < bytes.Length; i++)
                                    {
                                        bytes[i] ^= MessageCookie[i];
                                    }
                                    att.IP = BitConverter.ToUInt32(bytes);
                                }
                            }
                            att.Port = att.Port.ReverseEndianness();
                            IPEndPoint result = new IPEndPoint(new IPAddress(att.IP), att.Port);

                            if (att.AttributeType == AttributeType.MAPPED_ADDRESS)
                            {
                                publicEndPoint = result;
                            }
                        }
                        break;
                }
                offset += att.AttributeLength;
            }
        }

        return true;
    }
    else
    {
        throw new NotSupportedException("Server does not has OTHER_ADDRESS field set!");
    }
}

[Flags]
public enum ChangeRequest : uint
{
    ChangeIP = 1 << 2,
    ChangePort = 1 << 1
}

public enum AttributeType : ushort
{
    MAPPED_ADDRESS = 0x0001,
    RESPONSE_ORIGIN = 0x802b,
    OTHER_ADDRESS = 0x802c,
    XOR_MAPPED_ADDRESS = 0x0020,

    CHANGE_REQUEST = 0x0003
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct Header
{
    public Header()
    {
        MessageTransactionID = new byte[12];
        Random.Shared.NextBytes(MessageTransactionID);
    }

    public ushort MessageType;
    public ushort MessageLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] MessageCookie;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
    public byte[] MessageTransactionID;
}

[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct Attribute
{
    public const int HeaderLength = 4;

    [FieldOffset(0)]
    public AttributeType AttributeType;
    [FieldOffset(2)]
    public ushort AttributeLength;

    //Server To Client
    [FieldOffset(4)]
    public byte Reserved;
    [FieldOffset(5)]
    public byte ProtocolFamily;
    [FieldOffset(6)]
    public ushort Port;
    [FieldOffset(8)]
    public uint IP;

    //Client To Server
    [FieldOffset(4)]
    public ChangeRequest ChangeRequest;
}

public static class Extensions
{
    public static byte[] ToArray<T>(this T t) where T : struct
    {
        byte[] buffer = new byte[Marshal.SizeOf(t)];
        unsafe
        {
            fixed (byte* ptr = buffer)
                Marshal.StructureToPtr(t, (nint)ptr, false);
        }
        return buffer;
    }

    public static byte[] ToArray<T>(this T t, int size) where T : struct
    {
        byte[] buffer = new byte[Marshal.SizeOf(t)];
        unsafe
        {
            fixed (byte* ptr = buffer)
                Marshal.StructureToPtr(t, (nint)ptr, false);
        }
        byte[] bytes = new byte[size];
        Array.Copy(buffer, bytes, size);
        return bytes;
    }

    public static T ToStructure<T>(this byte[] buffer, int offset) where T : struct
    {
        unsafe
        {
            fixed (byte* ptr = buffer)
                return Marshal.PtrToStructure<T>(IntPtr.Add((IntPtr)ptr, offset));
        }
    }

    public static short ReverseEndianness(this short t)
    {
        return BinaryPrimitives.ReverseEndianness(t);
    }

    public static ushort ReverseEndianness(this ushort t)
    {
        return BinaryPrimitives.ReverseEndianness(t);
    }

    public static int ReverseEndianness(this int t)
    {
        return BinaryPrimitives.ReverseEndianness(t);
    }

    public static uint ReverseEndianness(this uint t)
    {
        return BinaryPrimitives.ReverseEndianness(t);
    }
}