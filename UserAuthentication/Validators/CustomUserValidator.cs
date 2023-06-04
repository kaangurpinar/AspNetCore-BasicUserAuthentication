using Microsoft.AspNetCore.Identity;
using UserAuthentication.Models;

namespace UserAuthentication.Validators
{
    public class CustomUserValidator : IUserValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        {
            var errors = new List<IdentityError>();

            if(user.UserName.Length < 3)
            {
                errors.Add(new IdentityError() { Code = "UserNameLength", Description = "Username must be at least 3 characters." });
            }

            if(user.Email.Substring(0, user.Email.IndexOf("@")) == user.UserName)
            {
                errors.Add(new IdentityError() { Code = "EmailContainsUserName", Description = "" });
            }
            
            if(errors.Any())
            {
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
