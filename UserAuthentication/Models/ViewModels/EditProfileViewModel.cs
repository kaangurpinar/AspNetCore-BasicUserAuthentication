using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class EditProfileViewModel
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Email { get; set; }

        public Gender Gender { get; set; } = Gender.Unknown;

        [Required]
        public DateTime BirthDay { get; set; }

        public bool EmailConfirmed { get; set; }
    }
}
