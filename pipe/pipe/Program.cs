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
                Console.WriteLine("[*]pipe.exe [pipeout] [pipein]");
                Console.WriteLine("[*]use default pipe");
            }



            string pipeServer_pipe_name = "spy";
            string pipeClient_pipe_name = "windbg";

            if (args.Length > 0)
            {

                pipeServer_pipe_name = args[0];
            }

            if (args.Length > 1)
            {
                pipeClient_pipe_name = args[1];
            }
            // var ws = new Wireshark.WiresharkSender("bacnet", pipeServer_pipe_name, pipeClient_pipe_name, 165);
            var ws = new Wireshark.WiresharkSender(pipeServer_pipe_name, pipeClient_pipe_name);
            Console.ReadLine();
            Console.WriteLine("pipe exit");
        }
    }
}
