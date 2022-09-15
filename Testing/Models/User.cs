using System.ComponentModel.DataAnnotations;

namespace Testing.Models;

public class User
{
	public string Name { get; set; } = string.Empty;
	public string Password { get; set; } = string.Empty;
	public string RefreshToken { get; set; } = string.Empty;
}
