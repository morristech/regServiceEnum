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
using System.Diagnostics;

namespace serviceEnum
{
    class Program
    {
        // getUserIdentities()
        // Args: None
        // Function: Obtain a list of all the users on the host.
        // Return: List of strings containing usernames
        static List<string> getUsersIdentities()
        {
            List<string> users = new List<string> { };

            // https://stackoverflow[.]com/questions/5247798/get-list-of-local-computer-usernames-in-windows
            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string name = envVar["Name"].ToString();
                users.Add(name);
            }

            return users;
        }

        // getGroupIdentities()
        // Args: None
        // Function: Obtain a list of all the LOCAL groups on the host.
        // Return: List of strings containing group names.
        static List<string> getGroupIdentities()
        {
            List<string> groups = new List<string> { };

            // https://stackoverflow[.]com/questions/5247798/get-list-of-local-computer-usernames-in-windows
            SelectQuery query = new SelectQuery("Win32_Group");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                string name = envVar["Name"].ToString();
                groups.Add(name);

            }
            return groups;
        }

        // getGroupMembers()
        // Args: string representing the group name to obtain the members list of
        // Function: Obtain a list of all the usernames that are apart of the specified group.
        // Return: List of strings containing all the users in the group.
        static List<string> getGroupMembers(string groupName)
        {
            List<string> membersList = new List<string> { };

            // https://stackoverflow[.]com/questions/2783584/getting-the-list-localadmins-for-a-set-of-server
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

        // getServices()
        // Args: None
        // Function: Obtain a list of registry keys associated with services on the host.
        // Return: A list of Registry Key objects, each associating with a specific Windows Service.
        static List<RegistryKey> getServices()
        {
            // This is the base hive of where service Registry keys are stored.
            const string servicesHive = "SYSTEM\\CurrentControlSet\\Services";
            RegistryKey rk = Registry.LocalMachine;
            RegistryKey services = rk.OpenSubKey(servicesHive);

            String[] serviceList = services.GetSubKeyNames();

            // These represent Kernel Drivers, File Drivers, Adapters and Recognizer Drivrs respectively.
            // Since this application is for exploiting userland services ( basically services that call a .exe),
            // We ignore anything with this service tpy.
            List<Int32> badTypes = new List<Int32> { 1, 2, 4, 8 };

            List<RegistryKey> servicesRegKeys = new List<RegistryKey> { };
            foreach (String s in serviceList)
            {
                RegistryKey service = services.OpenSubKey(s);

                // Checks if a type is specified, and if that type is one of the ones we don't want. If not,
                // add it to list of services.
                if (service.GetValueNames().Contains("Type") && !badTypes.Contains(Int32.Parse(service.GetValue("Type").ToString())))
                {
                    servicesRegKeys.Add(service);
                }

            }
            return servicesRegKeys;
        }

        // getServiceConfig()
        // Args: RegistryKey associated with a service.
        // Function: Enumerate the Registry Key's values, and convert it into a dictionary to more
        // easily access the values.
        // Return: Dictionary containing registry values of the key ( Name = Key, Data = Value)
        static Dictionary<string, object> getServiceConfig(RegistryKey service)
        {
            Dictionary<string, object> config = new Dictionary<string, object> { };

            // loop through name=>value pairs, associated the name to dict key, and value to dict value.
            String[] values = service.GetValueNames();
            foreach (string val in values)
            {
                config[val] = service.GetValue(val);
            }

            return config;
        }

        // imagePathToExecutable()
        // Args: string of an image path value, which is one of the registry key values for what the service executes.
        // Function: Properly parse out the executable name and arguments given to it. It will also trim unecessary quotations, etc.
        // Return: A dictionary containing two key-value mappings; a "file" key containing the name of the executable being executed,
        // and an "args" key containing all the arguments passed to the executable (both strings).
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

            else if (imagePath.ToLower().Contains(".bat"))
            {

                String[] parts = imagePath.Split(new[] { ".bat" }, StringSplitOptions.None);
                imageExecutable["file"] = parts[0] + ".bat";
                try
                {
                    imageExecutable["args"] = parts[1];
                }
                catch (Exception) { imageExecutable["args"] = null; }
            }

            return imageExecutable;
        }

        // Function: getAccessRules()
        // Args: string of the filename to obtain access rules of.
        // Function: Obtain a list of user/group => permissions mappings for the given file.
        // Return: A dictionary with the keys being User/Group names, and the values being the permissions
        // given to that user/group for the file.
        static Dictionary<string, string> getAccessRules(string filename)
        {
            // When checking access rules, quotations in the file name are a no no. So, if there's quotes in
            // the executable name (so quoted service paths), replace them with whitespace.
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

                    // some account names have the BUILTIN\ prefix, while others don't. This try catch statement takes
                    // care of either case.
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

            // Real men power through errors without actually handling them or even indicating to the user
            // that something went wrong.
            catch (System.Security.Principal.IdentityNotMappedException) { }
            catch (System.IO.FileNotFoundException) { }
            catch (System.InvalidOperationException) { }

            return accessRules;
        }

        // Function checkPermissions()
        // Args: the String representation of the rules given to a user/group for a file (these are the values of the
        // getAccessRules() return.
        // Function: Parse of the permissions string, and look for any exploitable permissions.
        // Return: A list of strings that represent any exploitable permissions.
        static List<string> checkPermissions(string ruleString)
        {
            // These are the perms that indicate we can modify the object, which is exploitable when it comes
            // to services.
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

        // printUnquotedPathAlert()
        // Args: name of the service, service config (dictionary) obtained by getServiceConfig().
        // Function: Prettily print out alerts of potentially exploitable unquoted service paths.
        // Return: None
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

        // printFileModifiableAlert()
        // Args: string of service name, service config dict from getServiceConfig(), exe dictionary from imageToExecutable(),
        // string representation of file permissions, string of username.
        // Function: Prettily print out an alert indicating the executable called by the service is modifiable by the current user.
        // Return: None
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

        // checkForUnquoted()
        // Args: None
        // Function: Parse image paths to try and find any unquoted service paths.
        // Return: None (will print out alert if anything is found).
        static void checkForUnquoted()
        {
            List<RegistryKey> services = getServices();
            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                if (config.ContainsKey("ImagePath"))
                {
                    string iPath = config["ImagePath"].ToString();
                    if (iPath.Contains(".exe") || iPath.Contains(".bat") ) 
                    {
                        Dictionary<string, string> iExecutable = imagePathToExecutable(iPath);
                        string iExe = iExecutable["file"];

                        // if the exe name has spaces, but no quotes, it can potentially be exploited.
                        if (!iExe.Contains('"') && iExe.Contains(" "))
                        {
                            printUnquotedPathAlert(service.Name, config);
                        }
                    }
                }
            }
        }

        // checkForModifiableExes()
        // Args: None
        // Function: Parse image paths to obtain the exe's being called, and check if those exe's are modifiable by current user.
        // Return: None (will print out alert if anything is found).
        static void checkForModifiableExes()
        {
            string myUser = Environment.UserName;
            List<RegistryKey> services = getServices();
            List<string> groups = getGroupIdentities();
            
            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                List<string> exploitablePerms = new List<string> { };
                if (config.ContainsKey("ImagePath"))
                {
                    string iPath = config["ImagePath"].ToString();

                    // we don't want to deal with system drivers. Technically previous restrictions in our code should
                    // prevent them from being in the service list, but double checking is always good.
                    if (!iPath.ToLower().Contains("sys") && !iPath.ToLower().Contains("driver"))
                    {
                        Dictionary<string, string> iExecutable = imagePathToExecutable(iPath);
                        string iExe = iExecutable["file"];
                        string iArgs = iExecutable["args"];
                        Dictionary<string, string> fileAccessRules = getAccessRules(iExe);
                        
                        foreach (KeyValuePair<string, string> rule in fileAccessRules)
                        {
                            // If there's a rule specifically for our user, check if those given permissions
                            // are exploitable (need to add support for when a SID is specified.
                            if (rule.Key.Equals(myUser))
                            {
                                exploitablePerms.AddRange(checkPermissions(rule.Value));
                            }

                            // if the identity is a group, we want to check if our current user is in that group,
                            // which would mean the permissions for that group apply to our user.
                            if (groups.Contains(rule.Key))
                            {
                                // Checks if we're in the group.
                                List<string> members = getGroupMembers(rule.Key);
                                if (members.Contains(myUser))
                                {
                                    exploitablePerms.AddRange(checkPermissions(rule.Value));
                                }
                            }
                        }
                        
                        // if we have any exploitable perms, tell the user.
                        if (exploitablePerms.Count > 0)
                        {
                            string permString = string.Join(",", exploitablePerms);
                            printFileModifiableAlert(service.Name, config, iExecutable, permString, myUser);

                        }
                    }    
                }
            }
        }
  
        // printServiceModifiableAlert()
        // Args: string of service name, service config dict from getServiceConfig, string representation of file permissions, string of user
        // Function: prettily print out alerts indicating that the registry key for a service is modifiable by the current user.
        // Return: None
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

        // checkRegistryPermissions()
        // Args: None
        // Function: check if the registry keys associated with services are modifiable by the current user.
        // Return: None (will print out alert if anything is found).
        static void checkRegistryPermissions()
        {
            string myUser = Environment.UserName;
            NTAccount account = new NTAccount(myUser);
            List<RegistryKey> services = getServices();
            List<string> groups = getGroupIdentities();

            foreach (RegistryKey service in services)
            {
                Dictionary<string, object> config = getServiceConfig(service);
                RegistrySecurity regSecurity = service.GetAccessControl();
                AuthorizationRuleCollection rules = regSecurity.GetAccessRules(true, true, (account).GetType());
                List<string> exploitablePerms = new List<string> { };
                foreach (RegistryAccessRule rule in rules)
                {
                    // Some identities have the BUILTIN\ prefix; this get's rid out it if it is there,
                    // but also handles the situations in which it's not.
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

                    // Checks if the identity is a group; if so, check if our user is within that group.
                    if (groups.Contains(identity))
                    {
                        List<string> members = getGroupMembers(identity);
                        if (members.Contains(myUser))
                        {
                            exploitablePerms.AddRange(checkPermissions(right));
                        }
                    }
                    else if (identity.Equals(myUser))
                    {
                        exploitablePerms.AddRange(checkPermissions(right));

                    }
           
                }

                if (exploitablePerms.Count > 0)
                {
                    string permString = string.Join(",", exploitablePerms);
                    printServiceModifiableAlert(service.Name, config, permString, myUser);

                }

            }
        }

        // printFullEnumeration()
        // Args: None
        // Function: display the complete enumeration of all services on the host.
        // Return: None
        static void printFullEnumeration()
        {
            // This dictionary can be used to convert numerical service type codes into their
            // string representation. Could have used an enum, but this worked better in practice.
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

            // This dictionary can be used to convert numerical start type codes into their
            // string representation.
            Dictionary<int, string> start = new Dictionary<int, string>
            {
                { 2, "Automatic" },
                { 0, "Boot" },
                { 4, "Disabled" },
                { 3, "Manual" },
                { 1, "System" }

            };

            // This dictionary can be used to convert numerical error handle codes into their
            // string representation.
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
            printFullEnumeration(); 
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("------------------------------------------------------");
            Console.WriteLine("|               Exploitable Vectors                  |");
            Console.WriteLine("------------------------------------------------------");
            Console.ResetColor();
            checkRegistryPermissions();
            checkForUnquoted();
            checkForModifiableExes();

        }
    }
}

