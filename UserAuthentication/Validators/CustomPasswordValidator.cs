using Microsoft.AspNetCore.Identity;
using UserAuthentication.Models;

namespace UserAuthentication.Validators
{
    public class CustomPasswordValidator : IPasswordValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string password)
        {
            var errors = new List<IdentityError>();

            if(user.UserName == password)
            {
                errors.Add(new IdentityError() { Code = "PasswordEqualsUsername", Description = "Password must not equal username." });
            }

            if(errors.Any())
            {
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
