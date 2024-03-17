using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace pipe
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[*]usage");
                Console.WriteLine("[*]pipe.exe [pipeout] [pipein] [wirehsrakpipe]");
                Console.WriteLine("[*]use default pipe");
            }



            string pipeServer_pipe_name = "spy";
            string pipeClient_pipe_name = "windbg";
            string wirehsrakpipe = "bacnet";

            if (args.Length > 0)
            {

                pipeServer_pipe_name = args[0];
            }

            if (args.Length > 1)
            {
                pipeClient_pipe_name = args[1];
            }


            if (args.Length > 2)
            {
                wirehsrakpipe = args[2];
            }

            // var ws = new Wireshark.WiresharkSender("bacnet", pipeServer_pipe_name, pipeClient_pipe_name, 165);
            Wireshark.WiresharkSender ws = new Wireshark.WiresharkSender(pipeServer_pipe_name, pipeClient_pipe_name);

            if (args.Length > 2)
            {
                //"C:\Program Files\Wireshark\Wireshark.exe"  -ni \\.\pipe\bacnet
                ws.WiresharCreate(wirehsrakpipe, 1);

            }

            Console.ReadLine();
            Console.WriteLine("pipe exit");
        }
    }
}
