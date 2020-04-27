# regServiceEnum
Enumerate Windows Services via the Registry for when you don't have permission for sc.exe.

Created by: @kindredsec

This script will perform a full enumeration of Windows services, as well as display any of the following potential exploitation vectors:
* Unquoted Service Path
* Modifiable Service Executable
* Modifiable Service

Everything is done via the registry and there is never a call to the *ServiceController*. 

Just run the binary with no command line arguments.
****
## Example Output:
**Locating exploitable vectors**
![Exploitable Vectors ](https://github.com/itsKindred/regServiceEnum/blob/master/images/exploitable_vectors.PNG)

**Generic Service Enumeration Example**

![Sample Service](https://github.com/itsKindred/regServiceEnum/blob/master/images/sample_service.PNG)
****
## To-Do:
- [ ] Add checks for Domain Users/Groups
- [ ] Build in option to specify a user to check for, not just your current user.
- [ ] Command line arguments to specify what to check for and what to output.
- [ ] Make checks to see if an unquoted service path is actually exploitable.
