using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Data.Entities
{
    [Table("Categories")]
    public class Category
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string CategoryName { get; set; }

        public int UserId { get; set; }

        //[ForeignKey(nameof(UserId))]
        [ForeignKey("UserId")]
        public AppUser AppUser { get; set; }
    }
}
