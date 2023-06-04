using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models.ViewModels
{
    public class EditRoleViewModel
    {
        [Required]
        public string Name { get; set; }
    }
}
