namespace UserAuthentication.Models.ViewModels
{
    public class UserViewModel
    {
        public string Id { get; set; }

        public string UserName { get; set; }

        public string Email { get; set; }

        public List<string> Roles { get; set; }

        public Gender Gender { get; set; }

        public DateTime BirthDay { get; set; }

        public DateTime CreatedAt { get; set; }
    }
}
