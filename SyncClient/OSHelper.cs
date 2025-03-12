using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SyncClient;

public class OSHelper
{
    public static string GetComputerName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return Environment.MachineName;
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return ExecuteCommand("scutil --get ComputerName").Trim();
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            string hostname;

            try
            {
                hostname = Environment.MachineName;
                if (!string.IsNullOrEmpty(hostname))
                    return hostname;
            }
            catch (Exception err)
            {
                Logger.Error<OSHelper>("Error fetching hostname, trying different method...", err);
            }

            try
            {
                hostname = ExecuteCommand("hostnamectl hostname").Trim();
                if (!string.IsNullOrEmpty(hostname))
                    return hostname;
            }
            catch (Exception err2)
            {
                Logger.Error<OSHelper>("Error fetching hostname again, using generic name...", err2);
                hostname = "linux device";
            }

            return hostname;
        }
        else
            return Environment.MachineName;
    }

    private static string ExecuteCommand(string command)
    {
        ProcessStartInfo processInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{command}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = new Process { StartInfo = processInfo })
        {
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output;
        }
    }
}
