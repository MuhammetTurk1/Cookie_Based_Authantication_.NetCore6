using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage ="Bu alanı doldurmanız zorunludur")]
        [StringLength(30,ErrorMessage ="this should be max 30 caracters")]
        public string Username { get; set; }


        //[DataType(DataType.Password)] //password kısmını password seklinde gösteriyor
        [Required(ErrorMessage ="Bu alanı doldurmanız zorunludur")]
        [MinLength(1, ErrorMessage = "this should be Min-1 caracters")]
        [MaxLength(16, ErrorMessage = "this should be M caracters")]
        public string Password { get; set; }
    }
}
