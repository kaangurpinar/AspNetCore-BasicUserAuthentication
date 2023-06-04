using Microsoft.AspNetCore.Identity;

namespace UserAuthentication.Models
{
    public enum Gender { Unknown, Male, Female }

    public class AppUser : IdentityUser
    {
        public Gender Gender { get; set; }

        public DateTime BirthDay { get; set; }

        public DateTime CreatedAt { get; set; }
    }
}
