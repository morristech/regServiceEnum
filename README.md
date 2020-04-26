# regServiceEnum
Enumerate Windows Services via the Registry for when you don't have permission for sc.exe.

This script will perform a full enumeration of Windows services, as well as display any of the following potential exploitation vectors:
* Unquoted Service Path
* Modifiable Service Executable
* Modifiable Service

Everything is done via the registry and there is never a call to the *ServiceController*. 

Example Output:
****
**Locating exploitable vectors**
![alt text](https://github.com/itsKindred/regServiceEnum/images/exploitable_vectors.png "Exploitable Vectors")

**Generic Service Enumeration Example**
![alt text](https://github.com/itsKindred/regServiceEnum/images/sample_service.png "Sample Service")

To-Do:
****
- [ ] Add checks for Domain Users/Groups
- [ ] Build in option to specify a user to check for, not just your current user.
- [ ] Command line arguments to specify what to check for and what to output.
- [ ] Make checks to see if an unquoted service path is actually exploitable.
