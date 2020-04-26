using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.ServiceProcess;
using System.Security;
using System.Reflection;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Collections;
using System.Data;
using System.Management;
using System.DirectoryServices.AccountManagement;
using System.Text.RegularExpressions;
using System.Threading;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.ComponentModel.Design;

namespace serviceEnum
{
    class Program
    {
        // Obtain a list of the identities on the host; this can be used to compare Permissions
        static List<string> getUsersIdentities()
        {
            List<string> users = new List<string> { };

            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string name = envVar["Name"].ToString();
                users.Add(name);
            }

            return users;
        }

        static List<string> getGroupIdentities()
        {
            List<string> groups = new List<string> { };
            SelectQuery query = new SelectQuery("Win32_Group");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string name = envVar["Name"].ToString();
                groups.Add(name);

            }
            return groups;
        }

        static List<string> getGroupMembers(string groupName)
        {
            List<string> membersList = new List<string> { };
            using (DirectoryEntry d = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer"))
            {
                using (DirectoryEntry g = d.Children.Find(groupName, "group"))
                {
                    object members = g.Invoke("Members", null);
                    foreach (object member in (IEnumerable)members)
                    {
                        DirectoryEntry x = new DirectoryEntry(member);
                        membersList.Add(x.Name);

                    }
                }
            }
            return membersList;
        }

        static List<RegistryKey> getServices()
        {
            const string servicesHive = "SYSTEM\\CurrentControlSet\\Services";
            RegistryKey rk = Registry.LocalMachine;
            RegistryKey services = rk.OpenSubKey(servicesHive);

            String[] serviceList = services.GetSubKeyNames();
            List<Int32> badTypes = new List<Int32> { 1, 2, 4, 8 };

            List<RegistryKey> servicesRegKeys = new List<RegistryKey> { };
            foreach (String s in serviceList)
            {
                RegistryKey service = services.OpenSubKey(s);
                if (service.GetValueNames().Contains("Type") && !badTypes.Contains(Int32.Parse(service.GetValue("Type").ToString())))
                {
                    servicesRegKeys.Add(service);
                }

            }
            return servicesRegKeys;
        }

        static Dictionary<string, object> getServiceConfig(RegistryKey service)
        {
            Dictionary<string, object> config = new Dictionary<string, object> { };
            String[] values = service.GetValueNames();
            foreach (string val in values)
            {
                config[val] = service.GetValue(val);
            }

            return config;
        }

        static Dictionary<string, string> imagePathToExecutable(string imagePath)
        {
            Dictionary<string, string> imageExecutable = new Dictionary<string, string> { };

            if (imagePath.ToLower().StartsWith("\""))
            {
                String[] parts = imagePath.Split(new[] { "\"" }, StringSplitOptions.None);
                imageExecutable["file"] = "\"" + parts[1] + "\"";
                if (parts.Length == 3)
                {
                    imageExecutable["args"] = null;
                }
                else
                {
                    string args = "";
                    for (int i = 2; i < parts.Length; i += 1)
                    {
                        // Just a janky formatting fix to get rid of an extra leading quotation.
                        if (i == 2) { args += parts[i]; } else { args += "\"" + parts[i]; }
                    }
                    imageExecutable["args"] = args;
                }

            }

            else if (imagePath.ToLower().Contains(".exe"))
            {

                String[] parts = imagePath.Split(new[] { ".exe" }, StringSplitOptions.None);
                imageExecutable["file"] = parts[0] + ".exe";
                try
                {
                    imageExecutable["args"] = parts[1];
                }
                catch (Exception) { imageExecutable["args"] = null; }
            }

            return imageExecutable;
        }

        static Dictionary<string, string> getAccessRules(string filename)
        {
            filename = filename.Replace('\"', ' ');
            Dictionary<string, string> accessRules = new Dictionary<string, string> { };
            try
            {
                FileInfo fInfo = new FileInfo(filename);
                FileSecurity fSecurity = fInfo.GetAccessControl();
                AuthorizationRuleCollection rules = fSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (FileSystemAccessRule rule in rules)
                {
                    FileSystemRights fsRights = rule.FileSystemRights;
                    IdentityReference identity = rule.IdentityReference.Translate(typeof(NTAccount));
                    try
                    {
                        string ntAccount = identity.ToString().Split('\\')[1];
                        string rights = fsRights.ToString();
                        accessRules[ntAccount] = rights;
                    }
                    catch (System.IndexOutOfRangeException)
                    {
                        string ntAccount = identity.ToString();
                        string rights = fsRights.ToString();
                        accessRules[ntAccount] = rights;
                    }
                }
            }
            catch (System.Security.Principal.IdentityNotMappedException) { }
            catch (System.IO.FileNotFoundException) { }
            catch (System.InvalidOperationException) { }

            return accessRules;
        }

        static List<string> checkPermissions(string ruleString)
        {
            List<string> goodPerms = new List<string> { "FullControl", "Write", "Modify" };

            List<string> exploitablePerms = new List<string> { };
            foreach (string perm in ruleString.Split(','))
            {
                if (goodPerms.Contains(perm.Trim()))
                {
                    exploitablePerms.Add(perm.Trim());
                }
            }

            return exploitablePerms;
        }

        static void printUnquotedPathAlert(string serviceName, Dictionary<string, object> serviceConfig)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("=========== EXPLOITABLE VECTOR ===========");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Service ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            // Some services don't have defined Display Names.
            try { Console.Write(serviceConfig["DisplayName"]); } catch (Exception) { Console.Write(serviceName); }
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(" utilizes an unquoted service path: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(serviceConfig["ImagePath"]);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(".\n");
            Console.WriteLine("This could possibly be leveraged to redirect service execution to a malicious binary!");
            Console.WriteLine();
            Console.WriteLine("Full Service Name: " + serviceName);
            Console.WriteLine("Full Execution Call: " + serviceConfig["ImagePath"]);
            Console.Write("Service Runs as : ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(serviceConfig["ObjectName"]);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("==========================================");
            Console.WriteLine();
            Console.ResetColor();
        }

        static void printFileModifiableAlert(string serviceName, Dictionary<string, object> serviceConfig, Dictionary<string, string> exe, string perms, string user)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("=========== EXPLOITABLE VECTOR ===========");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Service ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            // Some services don't have defined Display Names.
            try { Console.Write(serviceConfig["DisplayName"]); } catch (Exception) { Console.Write(serviceName); }
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(" calls the executable ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(exe["file"]);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(".\n");
            Console.Write("This service is Modifiable (");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(perms);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(") By your current user (");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(user);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(").");
            Console.WriteLine();
            Console.WriteLine("Full Service Name: " + serviceName);
            Console.WriteLine("Full Execution Call: " + exe["file"] + " " + exe["args"]);
            Console.Write("Service Runs as: ");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(serviceConfig["ObjectName"]);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("==========================================");
            Console.WriteLine();
            Console.ResetColor();

        }

        static void checkForUnquoted()
        {
            List<RegistryKey> services = getServices();
            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                if (config.ContainsKey("ImagePath"))
                {
                    string iPath = config["ImagePath"].ToString();
                    if (iPath.Contains(".exe"))
                    {
                        Dictionary<string, string> iExecutable = imagePathToExecutable(iPath);
                        string iExe = iExecutable["file"];
                        if (!iExe.Contains('"') && iExe.Contains(" "))
                        {
                            printUnquotedPathAlert(service.Name, config);
                        }
                    }
                }
            }
        }

        static void checkForModifiableExes()
        {
            string myUser = Environment.UserName;
            List<RegistryKey> services = getServices();
            List<string> groups = getGroupIdentities();

            // first check permissions of Image Paths of services
            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                if (config.ContainsKey("ImagePath"))
                {
                    string iPath = config["ImagePath"].ToString();
                    if (!iPath.ToLower().Contains("sys") && !iPath.ToLower().Contains("driver"))
                    {
                        Dictionary<string, string> iExecutable = imagePathToExecutable(iPath);
                        string iExe = iExecutable["file"];
                        string iArgs = iExecutable["args"];
                        Dictionary<string, string> fileAccessRules = getAccessRules(iExe);
                        foreach (KeyValuePair<string, string> rule in fileAccessRules)
                        {
                            if (rule.Key.Equals(myUser))
                            {
                                List<string> exploitablePerms = checkPermissions(rule.Value);
                            }
                            // Write, Modify or FullControl
                            // if the identity is a group, drill down the users of that group.
                            if (groups.Contains(rule.Key))
                            {
                                List<string> members = getGroupMembers(rule.Key);
                                if (members.Contains(myUser))
                                {
                                    List<string> exploitablePerms = checkPermissions(rule.Value);
                                    if (exploitablePerms.Count > 0)
                                    {
                                        string permString = string.Join(",", exploitablePerms);
                                        printFileModifiableAlert(service.Name, config, iExecutable, permString, myUser);

                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        static void printServiceModifiableAlert(string serviceName, Dictionary<string, object> serviceConfig, string perms, string user)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("=========== EXPLOITABLE VECTOR ===========");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Service ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            // Some services don't have defined Display Names.
            try { Console.Write(serviceConfig["DisplayName"]); } catch (Exception) { Console.Write(serviceName); }
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" is a modifiable service, which could allow you to alter what executable the service calls. ");
            Console.Write("This service is Modifiable (");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(perms);
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(") By your current user (");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(user);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(").");
            Console.WriteLine();
            Console.WriteLine("Full Service Name: " + serviceName);
            if (serviceConfig.ContainsKey("ObjectName"))
            {
                Console.Write("Service Runs as: ");
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine(serviceConfig["ObjectName"]);
            }
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("==========================================");
            Console.WriteLine();
            Console.ResetColor();

        }

        static void checkRegistryPermissions()
        {
            string myUser = Environment.UserName;
            NTAccount account = new NTAccount(myUser);
            List<RegistryKey> services = getServices();
            List<string> groups = getGroupIdentities();

            // first check permissions of Image Paths of services
            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                RegistrySecurity regSecurity = service.GetAccessControl();
                AuthorizationRuleCollection rules = regSecurity.GetAccessRules(true, true, (account).GetType());

                foreach (RegistryAccessRule rule in rules)
                {
                    string identity = "";
                    try
                    {
                        identity = rule.IdentityReference.ToString().Split('\\')[1];

                    }
                    catch (Exception)
                    {
                        identity = rule.IdentityReference.ToString();
                    }

                    string right = rule.RegistryRights.ToString();
                    if (groups.Contains(identity))
                    {
                        List<string> members = getGroupMembers(identity);
                        if (members.Contains(myUser))
                        {
                            List<string> exploitablePerms = checkPermissions(right);
                            if (exploitablePerms.Count > 0)
                            {
                                string permString = string.Join(",", exploitablePerms);
                                printServiceModifiableAlert(service.Name, config, permString, myUser);

                            }
                        }
                    }
                    else if (identity.Equals(myUser))
                    {
                        List<string> exploitablePerms = checkPermissions(right);
                        if (exploitablePerms.Count > 0)
                        {
                            string permString = string.Join(",", exploitablePerms);
                            printServiceModifiableAlert(service.Name, config, permString, myUser);

                        }
                    }
                }

            }
        }
        static void showFullEnumeration()
        {
            Dictionary<int, string> serviceType = new Dictionary<int, string>
            {
                { 4,  "Adapter" } , //Technically this is never going to happen since we filter it out, but just to be safe.
                { 2, "FileSystemDriver" }, //Technically this is never going to happen since we filter it out, but just to be safe.
                { 256, "InteractiveProcess" },
                { 1, "KernelDriver" }, //Technically this is never going to happen since we filter it out, but just to be safe.
                { 8, "RecognizerDriver" }, //Technically this is never going to happen since we filter it out, but just to be safe.
                { 16, "Win32OwnProcess" },
                { 32, "Win32ShareProcess" },
                { 96, "PerUserService" },
                { 224, "PerUserService" },
            };

            Dictionary<int, string> start = new Dictionary<int, string>
            {
                { 2, "Automatic" },
                { 0, "Boot" },
                { 4, "Disabled" },
                { 3, "Manual" },
                { 1, "System" }

            };

            Dictionary<int, string> error = new Dictionary<int, string>
            {
                { 0, "Ignore Error" },
                { 1, "Warning Only" },
                { 2, "Panic" },
                { 3, "Fail Startup" }
            };

            string myUser = Environment.UserName;
            List<RegistryKey> services = getServices();
            List<string> groups = getGroupIdentities();

            // first check permissions of Image Paths of services
            foreach (RegistryKey service in services)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("================================================");
                Console.ResetColor();
                Dictionary<string, object> config = getServiceConfig(service);

                String baseName = service.Name.Split('\\')[(service.Name.Split('\\').Length) - 1];
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write("SERVICE: ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(baseName);
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("------------------------------------");
                Console.ResetColor();
                if (config.ContainsKey("ImagePath"))
                {
                    Dictionary<string, string> exe = imagePathToExecutable(config["ImagePath"].ToString());
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("  Command Execution: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(exe["file"] + " " + exe["args"]);
                    Console.ForegroundColor = ConsoleColor.Gray;

                    Dictionary<string, string> accessRules = getAccessRules(exe["file"]);
                    if (accessRules.Count > 0)
                    {
                        Console.WriteLine("  -----------------");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("  Permissions of Executable: ");
                        Console.ResetColor();
                        foreach (KeyValuePair<string, string> pair in accessRules)
                        {
                            Console.Write("     ");
                            Console.ForegroundColor = ConsoleColor.White;
                            Console.Write(pair.Key + " => ");
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine(pair.Value);
                        }
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("  -----------------");
                    }
                }

                if (config.ContainsKey("DisplayName"))
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("  Display Name: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(config["DisplayName"]);
                    Console.ResetColor();
                }

                if (config.ContainsKey("Type"))
                {
                    int sType = Int32.Parse(config["Type"].ToString());
                    if (!serviceType.ContainsKey(sType))
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write("  Service Type: ");
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.WriteLine("Unknown");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write("  Service Type: ");
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.WriteLine(serviceType[sType]);
                        Console.ResetColor();
                    }
                }

                if (config.ContainsKey("DependOnService"))
                {
                    // Magic C# casting; no idea what's going on here.
                    List<string> dependencies = (config["DependOnService"] as IEnumerable<string>).Cast<string>().ToList();
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("  Dependencies: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(String.Join(",", dependencies));
                    Console.ResetColor();
                }

                if (config.ContainsKey("Start"))
                {
                    int startType = Int32.Parse(config["Start"].ToString());
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("  Start Type: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(start[startType]);
                    Console.ResetColor();
                }

                if (config.ContainsKey("ErrorControl"))
                {
                    int errorHandleType = Int32.Parse(config["ErrorControl"].ToString());
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("  Error Control: ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(error[errorHandleType]);
                    Console.ResetColor();
                }

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("================================================");
                Console.WriteLine();
                Console.ResetColor();

            }
        }
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("------------------------------------------------------");
            Console.WriteLine("|                Full Enumeration                    |");
            Console.WriteLine("------------------------------------------------------");
            Console.ResetColor();
            showFullEnumeration();
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("------------------------------------------------------");
            Console.WriteLine("|               Exploitable Vectors                  |");
            Console.WriteLine("------------------------------------------------------");
            Console.ResetColor();
            checkForUnquoted();
            checkForModifiableExes();
            checkRegistryPermissions();

        }
    }
}

