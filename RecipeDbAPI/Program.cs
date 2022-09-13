using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using RecipeORM.DatabaseSpecific;
using RecipeORM.EntityClasses;
using RecipeORM.HelperClasses;
using RecipeDbAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Data;

var builder = WebApplication.CreateBuilder(args);

// services
builder.Services.AddCors(options =>
{
	options.AddPolicy("Cors Policy",
		policy =>
		{
			policy
				.WithOrigins(builder.Configuration["FrontendOrigin"])
				.AllowAnyHeader()
				.AllowAnyMethod()
				.WithExposedHeaders("IS-TOKEN-EXPIRED")
				.AllowCredentials();
		});
});

builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

builder.Services.AddAuthentication(x =>
{
	x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
	.AddJwtBearer(o =>
	{
		var Key = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
		o.SaveToken = true;
		o.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = false,
			ValidateAudience = false,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = builder.Configuration["JWT:Issuer"],
			ValidAudience = builder.Configuration["JWT:Audience"],
			IssuerSigningKey = new SymmetricSecurityKey(Key),
			ClockSkew = TimeSpan.Zero
		};
		o.Events = new JwtBearerEvents
		{
			OnAuthenticationFailed = context =>
			{
				if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
				{
					context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
				}
				return Task.CompletedTask;
			}
		};
	});

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
	options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
	options.RoutePrefix = string.Empty;
});

app.UseHttpsRedirection();
app.UseCors("Cors Policy");
app.UseAuthentication();
app.UseAuthorization();

string GenerateRefreshToken()
{
	var randomNumber = new byte[32];
	using (var rng = RandomNumberGenerator.Create())
	{
		rng.GetBytes(randomNumber);
		return Convert.ToBase64String(randomNumber);
	}
}

JWToken? GenerateJWT(User user)
{
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenKey = Encoding.UTF8.GetBytes(app.Configuration["JWT:Key"]);
	var tokenDescriptor = new SecurityTokenDescriptor
	{
		Subject = new ClaimsIdentity(new Claim[]
		{
				new Claim(ClaimTypes.Name, user.Name)
		}),
		Expires = DateTime.UtcNow.AddMinutes(10),
		SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return new JWToken { Token = tokenHandler.WriteToken(token), RefreshToken = GenerateRefreshToken() };
}

JWToken? Authenticate(User user)
{
	PasswordHasher<string> pw = new();

	if (!usersList.Any(x => x.Name == user.Name && pw.VerifyHashedPassword(user.Name, x.Password, user.Password) == PasswordVerificationResult.Success))
	{
		return null;
	}

	// Else we generate JSON Web Token
	return GenerateJWT(user);
}

JWToken? Refresh(JWToken jwt)
{
	User user;

	if (usersList.Find(x => x.RefreshToken == jwt.RefreshToken) is User tempUser)
		user = tempUser;
	else
		return null;

	// Else we generate JSON Web Token
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenKey = Encoding.UTF8.GetBytes(app.Configuration["JWT:Key"]);
	var tokenDescriptor = new SecurityTokenDescriptor
	{
		Subject = new ClaimsIdentity(new Claim[]
		{
				new Claim(ClaimTypes.Name, user.Name)
		}),
		Expires = DateTime.UtcNow.AddMinutes(10),
		SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return new JWToken { Token = tokenHandler.WriteToken(token), RefreshToken = GenerateRefreshToken() };
}

// user enpoint
app.MapPost("/register", async (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	if (user.Name == String.Empty || user.Password == String.Empty || usersList.Exists(oldUser => oldUser.Name == user.Name))
	{
		return Results.BadRequest();
	}

	PasswordHasher<string> pw = new();
	user.Password = pw.HashPassword(user.Name, user.Password);
	usersList.Add(user);

	var token = GenerateJWT(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	user.RefreshToken = token.RefreshToken;
	await SaveAsync();
	return Results.Created($"/users/{user.Name}", token);
});

app.MapPost("/login", async (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	var token = Authenticate(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	PasswordHasher<string> pw = new();

	if (usersList.Find(x => x.Name == user.Name && pw.VerifyHashedPassword(user.Name, x.Password, user.Password) == PasswordVerificationResult.Success) is User tempUser)
	{
		tempUser.RefreshToken = token.RefreshToken;
		await SaveAsync();
	}

	return Results.Ok(token);
});

app.MapGet("/antiforgery/token", [Authorize] (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
			new CookieOptions { Secure = true, HttpOnly = false, SameSite = SameSiteMode.None });
});

app.MapPost("/refresh", async (JWToken jwt) =>
{
	var token = Refresh(jwt);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	if (usersList.Find(x => x.RefreshToken == jwt.RefreshToken) is User tempUser)
	{
		usersList.Remove(tempUser);
		tempUser.RefreshToken = token.RefreshToken;
		usersList.Add(tempUser);
		await SaveAsync();
	}

	return Results.Ok(token);
});

// recipe endpoints
app.MapGet("/recipes", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	return Results.Ok(recipesList);
});

app.MapGet("/recipes/{id}", [Authorize] async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPost("/recipes", [Authorize] async (Recipe recipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	using (DataAccessAdapter adapter = new())
	{
		adapter.StartTransaction(IsolationLevel.ReadCommitted, "Insert Recipe");
		try
		{
			var recipeEntity = new RecipeEntity();
			recipeEntity.Id = Guid.NewGuid();
			recipeEntity.Title = recipe.Title;
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception();

			// create instruction entities
			foreach (var instruction in recipe.Instructions)
			{
				var instructionEntity = new InstructionEntity
				{
					Id = Guid.NewGuid(),
					Text = instruction,
					Recipe = recipeEntity
				};
				if (!adapter.SaveEntity(instructionEntity))
					throw new Exception();
			}

			// create ingredient entities
			foreach (var ingredient in recipe.Ingredients)
			{
				var ingredientEntity = new IngredientEntity
				{
					Id = Guid.NewGuid(),
					Name = ingredient,
					Recipe = recipeEntity
				};
				if (!adapter.SaveEntity(ingredientEntity))
					throw new Exception();
			}

			// create category entities
			foreach (var category in recipe.Categories)
			{
				var categoryEntity = new CategoryEntity(category);
				if (!adapter.FetchEntity(categoryEntity))
					throw new Exception();

				var recipeCategoryDictionaryEntity = new RecipeCategoryDictionaryEntity()
				{
					Recipe = recipeEntity,
					Category = categoryEntity
				};
				if (!adapter.SaveEntity(recipeCategoryDictionaryEntity))
					throw new Exception();
			}

			adapter.Commit();
			return Results.Created($"/recipes/{recipe.Id}", recipe);
		}
		catch (Exception)
		{
			// Rollback if anything goes wrong
			adapter.Rollback();
			return Results.BadRequest();
		}
	}
});

app.MapDelete("/recipes/{id}", [Authorize] async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		await SaveAsync();
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPut("/recipes/{id}", [Authorize] async (Recipe editedRecipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == editedRecipe.Id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		recipesList.Add(editedRecipe);
		recipesList = recipesList.OrderBy(o => o.Title).ToList();
		await SaveAsync();
		return Results.NoContent();
	}
	return Results.NotFound();
});

// category endpoints
app.MapGet("/categories", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	var categories = new EntityCollection<CategoryEntity>();
	using (var adapter = new DataAccessAdapter())
	{
		adapter.FetchEntityCollection(categories, null);
	}
	return Results.Ok(categories.Select(x => x.Name).ToList());
});

app.MapPost("/categories", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	var categoryEntity = new CategoryEntity(category);
	try
	{
		using (DataAccessAdapter adapter = new())
		{
			var result = adapter.SaveEntity(categoryEntity);
			if(result)
			{
				return Results.Created($"/categories/{category}", category);
			}
			else
			{
				return Results.BadRequest();
			}
		}
	}
	catch (Exception)
	{
		return Results.BadRequest();
	}
});

app.MapDelete("/categories/{category}", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	if (category == String.Empty)
	{
		return Results.BadRequest();
	}

	try
	{
		var categoryEntity = new CategoryEntity(category);
		using (DataAccessAdapter adapter = new())
		{
			var result = adapter.DeleteEntity(categoryEntity);
			if (result)
			{
				return Results.Ok(category);
			}
			else
			{
				return Results.NotFound();
			}
		}
	}
	catch (Exception)
	{
		return Results.Problem();
	}
});

app.MapPut("/categories/{category}", [Authorize] async (string category, string editedCategory, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (editedCategory == String.Empty)
	{
		return Results.BadRequest();
	}

	try
	{
		var categoryEntity = new CategoryEntity(category);
		using (DataAccessAdapter adapter = new())
		{
			adapter.FetchEntity(categoryEntity);
			categoryEntity.Name = editedCategory;
			var result = adapter.SaveEntity(categoryEntity);
			if (result)
			{
				return Results.NoContent();
			}
			else
			{
				return Results.NotFound();
			}
		}
	}
	catch (Exception)
	{
		return Results.Problem();
	}
});

app.Run();