using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class SignUpViewModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public Gender Gender { get; set; } = Gender.Unknown;

        [Required]
        public DateTime BirthDay { get; set; }

        public bool RememberMe { get; set; }
    }
}
