/**************************************************************************
*                           MIT License
* 
* Copyright (C) 2015 Frederic Chaxel <fchaxel@free.fr>
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*********************************************************************/
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Threading;
using pipe;
//
// object creation could be done with 
//      var ws=new Wireshark.WiresharkSender("bacnet",165);  // pipe name is \\.\pipe\bacnet
//
// data to wireshark could be sent with something like that
//      if (ws.isConnected)
//          ws.SendToWireshark(new byte[]{0x55,0xFF,0,5,6,0,0,4}, 0, 8);
//
// Wireshark can be launch with : Wireshark -ni \\.\pipe\bacnet
//
// ... enjoy
//
namespace Wireshark
{
    // Pcap Global Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_g
    {
        UInt32 magic_number;   /* magic number */
        UInt16 version_major;  /* major version number */
        UInt16 version_minor;  /* minor version number */
        Int32 thiszone;       /* GMT to local correction */
        UInt32 sigfigs;        /* accuracy of timestamps */
        UInt32 snaplen;        /* max length of captured packets, in octets */
        UInt32 network;        /* data link type */

        public pcap_hdr_g(UInt32 snaplen, UInt32 network)
        {
            magic_number = 0xa1b2c3d4;
            version_major = 2;
            version_minor = 4;
            thiszone = 0;
            sigfigs = 0;
            this.snaplen = snaplen;
            this.network = network;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialization could be required on some systems
        // work well on Win32, Win64 .NET 3.0 to 4.5
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    // Pcap Packet Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_p
    {
        UInt32 ts_sec;         /* timestamp seconds */
        UInt32 ts_usec;        /* timestamp microseconds */
        UInt32 incl_len;       /* number of octets of packet saved in file */
        UInt32 orig_len;       /* actual length of packet */

        public pcap_hdr_p(UInt32 lenght, UInt32 datetime, UInt32 microsecond)
        {
            incl_len = orig_len = lenght;
            ts_sec = datetime;
            ts_usec = microsecond;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialise could be required on some system
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    public class WiresharkSender
    {
        NamedPipeServerStream WiresharkPipe;
        private NamedPipeClientStream pipeClient;
        private NamedPipeServerStream pipeServer;
        private byte[] inbufClient;
        private byte[] outbufClient;
        private byte[] inbufServer;
        private byte[] outbufServer;
        private List<byte> wiresharkbufferClient = new List<byte>();
        private List<byte> wiresharkbufferServer = new List<byte>();

        /*
        private byte[] magic_bytes =
        {
            0x4d, 0x44, 0x42, 0x47
        };
        */

        private byte[] magic_bytes = System.Linq.Enumerable.Repeat((byte)0x30, 4).ToArray();
        private byte[] magic_bytes_ctrl = System.Linq.Enumerable.Repeat((byte)0x69, 4).ToArray();
        private byte[] magic_bytes_break = System.Linq.Enumerable.Repeat((byte)0x62, 4).ToArray();

        private int DefaultBufferLength = 0x1000;
        public Mutex nodelock = new Mutex();
        bool IsConnected = false;

        string pipe_name;
        string pipeServer_pipe_name;
        string pipeClient_pipe_name;
        UInt32 pcap_netid;

        object verrou = new object();

        //public WiresharkSender(string pipe_name, string pipeServer_pipe, string pipeClient_pipe,UInt32 pcap_netid)
        public WiresharkSender( string pipeServer_pipe, string pipeClient_pipe)
        {
           // this.pipe_name = pipe_name;
            //this.pcap_netid = pcap_netid;
            pipeServer_pipe_name = pipeServer_pipe;
            pipeClient_pipe_name = pipeClient_pipe;
            // Open the pipe and wait to Wireshark on a background thread
            /*Thread th = new Thread(PipeCreate);
            th.IsBackground = true;
            th.Start();*/
            Thread th2 = new Thread(PipeCreateWindbg);
            th2.IsBackground = true;
            th2.Start();
        }

        private void PipeCreate()
        {

            try
            {
                WiresharkPipe = new NamedPipeServerStream(pipe_name, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                // Wait
                WiresharkPipe.WaitForConnection();
                Console.WriteLine("WiresharkPipe IsConnected");
                // Wireshark Global Header
                pcap_hdr_g p = new pcap_hdr_g(65535, pcap_netid);
                byte[] bh = p.ToByteArray();
                WiresharkPipe.Write(bh, 0, bh.Length);

                IsConnected = true;

            }
            catch { }

        }


        private void PipeCreateWindbg()
        {
            try
            {
                pipeServer =
                    new NamedPipeServerStream(pipeServer_pipe_name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

                pipeServer.WaitForConnection();
                Console.WriteLine("pipeServer:=> "+ pipeServer_pipe_name + " Is Connected ,Server session established");
                pipeClient =
                    new NamedPipeClientStream(".", pipeClient_pipe_name, PipeDirection.InOut, PipeOptions.Asynchronous);

                pipeClient.Connect();
                Console.WriteLine("pipeClient:=> " + pipeClient_pipe_name+ " Is Connected ,Client session established");


                inbufClient = new byte[DefaultBufferLength];

                outbufClient = new byte[DefaultBufferLength];

                inbufServer = new byte[DefaultBufferLength];

                outbufServer = new byte[DefaultBufferLength];

                Console.WriteLine("pipeClient.InBufferSize:=>" + pipeClient.InBufferSize + " pipeClient.OutBufferSize:=>" + pipeClient.OutBufferSize + "pipeServer.InBufferSize:=>" + pipeServer.InBufferSize + "pipeServer.OutBufferSize:=>" + pipeServer.OutBufferSize);
                Thread th1 = new Thread(PipeRead);
                th1.IsBackground = true;
                th1.Start();


                Thread th2 = new Thread(PipeWrite);
                th2.IsBackground = true;
                th2.Start();
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private void pipeClientBeginReadAsyncCallback(IAsyncResult ar)
        {
            int lenread = pipeClient.EndRead(ar);

            //Console.WriteLine("pipeClient EndRead " + lenread);
            SendToWireshark(wiresharkbufferClient,outbufClient, 0, lenread,false);
            Array.Copy(outbufClient, 0, inbufServer, 0, lenread);
            pipeServer.BeginWrite(inbufServer, 0, lenread, pipeClientBeginWriteAsyncCallback, lenread);
            pipeClient.BeginRead(outbufClient, 0, DefaultBufferLength, pipeClientBeginReadAsyncCallback, null);

        }

        private void pipeClientBeginWriteAsyncCallback(IAsyncResult ar)
        {
            int lenwrite = (int)ar.AsyncState;
            pipeServer.EndWrite(ar);
            //   Console.WriteLine("pipeServer EndWrite " + lenwrite);

        }

        private void PipeRead()
        {
            pipeClient.BeginRead(outbufClient, 0, DefaultBufferLength, pipeClientBeginReadAsyncCallback, null);

        }
        private void pipeServerBeginReadAsyncCallback(IAsyncResult ar)
        {
            int lenread = pipeServer.EndRead(ar);

            // Console.WriteLine("pipeServer EndRead " + lenread);
            SendToWireshark(wiresharkbufferServer,outbufServer, 0, lenread,true);
            Array.Copy(outbufServer, 0, inbufClient, 0, lenread);
            pipeClient.BeginWrite(inbufClient, 0, lenread, pipeServerBeginWriteAsyncCallback, lenread);
            pipeServer.BeginRead(outbufServer, 0, DefaultBufferLength, pipeServerBeginReadAsyncCallback, null);

        }

        private void pipeServerBeginWriteAsyncCallback(IAsyncResult ar)
        {
            int lenwrite = (int)ar.AsyncState;
            pipeClient.EndWrite(ar);
            // Console.WriteLine("pipeClient EndWrite " + lenwrite);

        }

        private void PipeWrite()
        {
            pipeServer.BeginRead(outbufServer, 0, DefaultBufferLength, pipeServerBeginReadAsyncCallback, null);

        }



        public bool isConnected
        {
            get { return IsConnected; }
        }

        private UInt32 DateTimeToUnixTimestamp(DateTime dateTime)
        {
            return (UInt32)(dateTime - new DateTime(1970, 1, 1).ToLocalTime()).TotalSeconds;
        }

        public bool SendToWireshark(List<byte> wiresharkbuffer,byte[] buffer, int offsetorg, int lenght, bool fromhost)
        {
            nodelock.WaitOne();
            wiresharkbuffer.AddRange(buffer.Take(lenght));
            int oldwiresharkbufferlen = wiresharkbuffer.Count;
            List<int> magicoffsets = new List<int>();
            List<byte[]> splitbuf = new List<byte[]>();
            for (int i = 0; i < wiresharkbuffer.Count; i++)
            {
                if (wiresharkbuffer.Count - i >= magic_bytes.Length)
                {
                    byte[] cmpbuf = wiresharkbuffer.Skip(i).Take(4).ToArray();
                    if (cmpbuf.SequenceEqual(magic_bytes)| cmpbuf.SequenceEqual(magic_bytes_ctrl)| cmpbuf.SequenceEqual(magic_bytes_break))
                    {
                        magicoffsets.Add(i);
                    }
                }
            }

            int startoffset = 0;
            int nextoffset = 0;
            bool startskip = false;
            if (magicoffsets.Count == 1)
            {
                nextoffset = magicoffsets.FirstOrDefault();
                if (nextoffset != 0)
                {
                    splitbuf.Add(wiresharkbuffer.Take(nextoffset).ToArray());
                }
            }
            else
            {
                foreach (int offset in magicoffsets.OrderBy(h=>h))
                {
                    if (startoffset == 0&& !startskip)
                    {
                        startskip = true;
                        startoffset = offset;
                        if (startoffset != 0)
                        {
                            splitbuf.Add(wiresharkbuffer.Take(startoffset).ToArray());
                        }
                    }
                    else
                    {
                        if (nextoffset != 0)
                        {
                            startoffset = nextoffset;
                        }

                        nextoffset = offset;
                        int nowlen = nextoffset - startoffset;
                        if (nowlen > 0)
                        {
                            splitbuf.Add(wiresharkbuffer.Skip(startoffset).Take(nowlen).ToArray());
                        }

                    }
                }
            }

            if (nextoffset != 0)
            {
                List<byte> remainbuf = wiresharkbuffer.Skip(nextoffset).ToList();
                wiresharkbuffer.Clear();
                if (remainbuf.Count > 0)
                {
                    wiresharkbuffer.AddRange(remainbuf);
                }
            }
            else if (magicoffsets.Count == 1)
            {
                if (wiresharkbuffer.Count == 1)
                {
                    wiresharkbuffer.Clear();
                }
            }

            int newwiresharkbufferlen = wiresharkbuffer.Count;
            int writelen = oldwiresharkbufferlen-newwiresharkbufferlen  ;
            nodelock.ReleaseMutex();
            int writecount = 0;
            int magicoffsetscount = magicoffsets.Count;
            int splitbufscount = splitbuf.Count;
            foreach (byte[] tmpbuf in splitbuf.Where(h => h.Length > 1))
            {
                //SendToWireshark(tmpbuf, 0, tmpbuf.Length, DateTime.Now);
                PacketWriter.Current.WritePactet(tmpbuf,fromhost);
                writecount++;
            }

            if (writecount > 0)
            {
                Console.WriteLine("Wireshark writecount " + writecount+ " magicoffsets "+magicoffsetscount + " splitbuf "+ splitbufscount + " oldlen "+ oldwiresharkbufferlen+" newlen "+ newwiresharkbufferlen+" rawlen "+ writelen);
            }

            if (oldwiresharkbufferlen == newwiresharkbufferlen&& splitbufscount > 0)
            {
                Console.WriteLine("malformed packet warning");
            }
            return true;
            //  
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, DateTime date)
        {
            UInt32 date_sec, date_usec;

            // Suppress all values for ms, us and ns
            DateTime d2 = new DateTime((date.Ticks / (long)10000000) * (long)10000000);

            date_sec = DateTimeToUnixTimestamp(date);
            date_usec = (UInt32)((date.Ticks - d2.Ticks) / 10);

            return SendToWireshark(buffer, offset, lenght, date_sec, date_usec);
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, UInt32 date_sec, UInt32 date_usec)
        {
            if (IsConnected == false)
                return false;

            if (buffer == null) return false;
            if (buffer.Length < (offset + lenght)) return false;

            pcap_hdr_p pHdr = new pcap_hdr_p((UInt32)lenght, date_sec, date_usec);
            byte[] b = pHdr.ToByteArray();

            try
            {
                // Wireshark Header
                WiresharkPipe.Write(b, 0, b.Length);
                // Bacnet packet
                WiresharkPipe.Write(buffer, offset, lenght);
            }
            catch (System.IO.IOException)
            {
                // broken pipe, try to restart
                IsConnected = false;
                WiresharkPipe.Close();
                WiresharkPipe.Dispose();
                Thread th = new Thread(PipeCreate);
                th.IsBackground = true;
                th.Start();
                return false;
            }
            catch (Exception)
            {
                // Unknow error, not due to the pipe
                // No need to restart it
                return false;
            }

            return true;
        }

    }
}
