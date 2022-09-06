namespace RecipeDbAPI.Models;

public class JWToken
{
	public string Token { get; set; } = string.Empty;
	public string RefreshToken { get; set; } = string.Empty;
}
