using Microsoft.AspNetCore.Identity;

namespace UserAuthentication.Models
{
    public class AppRole : IdentityRole
    {
        public DateTime CreatedAt { get; set; }
    }
}
