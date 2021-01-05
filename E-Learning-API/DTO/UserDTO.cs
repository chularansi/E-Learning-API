using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.DTO
{
    public class UserDTO
    {
        [Required]
        [EmailAddress]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }

    public class UserRegisterDTO
    {
        [Required]
        public string FirstName { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        [EmailAddress]
        public string UserName { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [StringLength(15, ErrorMessage = "Your Password is limited to {2} to {1} characters", MinimumLength = 6)]
        public string Password { get; set; }
    }
}
