﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class is used to check user identity and rights
    /// </summary>
    public static class UserIdentityHandler
    {
        /// <summary>
        /// Checks if currently logged user has administrator rights
        /// </summary>
        /// <returns>True if user is administrator</returns>
        public static bool IsUserAdministrator()
        {
            bool isAdmin;
            WindowsIdentity user = null;
            try
            {
                user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (UnauthorizedAccessException ex)
            {
                isAdmin = false;
            }
            catch (Exception ex)
            {
                isAdmin = false;
            }
            finally
            {
                if (user != null)
                {
                    user.Dispose();
                }
            }

            return isAdmin;
        }
    }
}
