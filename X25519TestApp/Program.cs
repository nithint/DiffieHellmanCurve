using DiffieHellmanCurveLib;
using System;

namespace X25519TestApp
{
    class Program
    {
        /// <summary>
        /// 
        /// </summary>
        /// <remarks>
        /// The certificates used in this project were generated using openssl but the output files were hand-edited to remove the 
        /// openssl wrapper text (ex: BEGIN PRIVATE KEY) etc.
        /// </remarks>
        /// <param name="args"></param>
        public static async System.Threading.Tasks.Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                var server = new TestServer();
                var client = new TestClient();
                Console.WriteLine($"Original message from server: {client.RetrieveMessage(server)}");
                return;
            }

            switch (args[0])
            {
                case "-h":
                    DisplayHelp();
                    break;
                default:
                    var url = args[0];
                    var client = new TestClient();
                    Console.WriteLine($"Original message from server: {await client.RetrieveMessage(url)}");
                    break;
            }

        }

        private static void DisplayHelp()
        {
            Console.WriteLine("x25519TestApp");
            Console.WriteLine("Runs DH key exchange protocol using curve 25519");
            Console.WriteLine(" [url] = Runs DH key exchange against the url");
            Console.WriteLine(" -h = Prints this help text");
        }
    }
}
