using Microsoft.AspNetCore.Identity;

namespace UserAuthentication.Validators
{
    public class CustomErrorDescriber : IdentityErrorDescriber
    {
        public override IdentityError InvalidUserName(string userName)
        {
            return new IdentityError() { Code = "InvalidUserName", Description = $"{userName} is invalid." };
        }

        public override IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError() { Code = "DuplicateUserName", Description = $"{userName} is already in use." };
        }

        public override IdentityError InvalidEmail(string email)
        {
            return new IdentityError() { Code = "InvalidEmail", Description = $"{email} is invalid." };
        }

        public override IdentityError DuplicateEmail(string email)
        {
            return new IdentityError() { Code = "DuplicateEmail", Description = $"{email} is already in use." };
        }

        public override IdentityError PasswordTooShort(int length)
        {
            return new IdentityError() { Code = "PasswordTooShort", Description = $"Password should be at least {length} characters." };
        }
    }
}
