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

Recipe RecipeEntityToModel(RecipeEntity recipeEntity)
{
	Recipe recipe = new Recipe
	{
		Id = recipeEntity.Id,
		Title = recipeEntity.Title,
		Categories = new(),
		Ingredients = new(),
		Instructions = new()
	};

	foreach (var instruction in recipeEntity.Instructions)
	{
		recipe.Instructions.Add(instruction.Text);
	}

	foreach (var ingredient in recipeEntity.Ingredients)
	{
		recipe.Instructions.Add(ingredient.Name);
	}

	foreach (var category in recipeEntity.RecipeCategoryDictionaries)
	{
		recipe.Instructions.Add(category.CategoryName);
	}

	return recipe;
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

// user enpoint
app.MapPost("/register", async (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	using (DataAccessAdapter adapter = new())
	{
		var userEntity = new UserEntity
		{
			Username = user.Name,
			Password = user.Password
		};

		if (user.Name == String.Empty || user.Password == String.Empty || adapter.FetchEntity(userEntity))
		{
			return Results.BadRequest();
		}

		PasswordHasher<string> pw = new();
		user.Password = pw.HashPassword(user.Name, user.Password);

		var token = GenerateJWT(user);

		if (token == null)
			return Results.Unauthorized();

		userEntity.RefreshToken = token.RefreshToken;

		var result = adapter.SaveEntity(userEntity);
		if (result)
		{
			return Results.Created($"/categories/{user.Name}", user);
		}
		else
		{
			return Results.BadRequest();
		}
	}
});

app.MapPost("/login", async (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	using (DataAccessAdapter adapter = new())
	{
		var userEntity = new UserEntity
		{
			Username = user.Name,
			Password = user.Password
		};

		PasswordHasher<string> pw = new();
		if (adapter.FetchEntity(userEntity) && pw.VerifyHashedPassword(user.Name, userEntity.Password, user.Password) == PasswordVerificationResult.Success)
		{
			return Results.Unauthorized();
		}
		var token = GenerateJWT(user);

		if (token == null)
		{
			return Results.Unauthorized();
		}

		userEntity.RefreshToken = token.RefreshToken;

		adapter.SaveEntity(userEntity);
		return Results.Ok(token);
	}
});

app.MapGet("/antiforgery/token", [Authorize] (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
			new CookieOptions { Secure = true, HttpOnly = false, SameSite = SameSiteMode.None });
});

app.MapPost("/refresh", async (JWToken jwt) =>
{
	using (DataAccessAdapter adapter = new())
	{
		var userEntity = new UserEntity
		{
			RefreshToken = jwt.RefreshToken
		};

		if(adapter.FetchEntityUsingUniqueConstraint(userEntity, null))
		{
			var token = GenerateJWT(new User
			{
				Name = userEntity.Username,
				Password = userEntity.Password
			});

			if (token == null)
				return Results.Unauthorized();

			userEntity.RefreshToken = token.RefreshToken;
			adapter.SaveEntity(userEntity);
			return Results.Ok(token);
		}
	}
	return Results.Unauthorized();
});

// recipe endpoints
app.MapGet("/recipes", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	var recipes = new EntityCollection<RecipeEntity>();
	using (var adapter = new DataAccessAdapter())
	{
		adapter.FetchEntityCollection(recipes, null);
	}

	var recipeList = new List<Recipe>();

	foreach (var recipe in recipes)
	{
		recipeList.Add(RecipeEntityToModel(recipe));
	}

	return Results.Ok(recipeList);
});

app.MapGet("/recipes/{id}", [Authorize] async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	var recipeEntity = new RecipeEntity(id);
	using (DataAccessAdapter adapter = new())
	{
		if (adapter.FetchEntity(recipeEntity))
			return Results.Ok(RecipeEntityToModel(recipeEntity));
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

			// create instruction entities
			foreach (var instruction in recipe.Instructions)
			{
				var instructionEntity = new InstructionEntity
				{
					Id = Guid.NewGuid(),
					Text = instruction,
					Recipe = recipeEntity
				};
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
			}

			// create recipeCategoryDictionary entities
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
			}

			// Save all entities recursively
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception();
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

	using (DataAccessAdapter adapter = new())
	{
		var recipeEntity = new RecipeEntity(id);
		try
		{
			if (!adapter.FetchEntity(recipeEntity))
				return Results.NotFound();
			recipeEntity.IsActive = false;
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception("Could Not Save");
			return Results.Ok(RecipeEntityToModel(recipeEntity));
		}
		catch (Exception)
		{
			return Results.NotFound();
		}
	}
});

app.MapPut("/recipes/{id}", [Authorize] async (Recipe editedRecipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);

	using (DataAccessAdapter adapter = new())
	{
		adapter.StartTransaction(IsolationLevel.ReadCommitted, "Insert Recipe");
		try
		{
			var recipeEntity = new RecipeEntity(editedRecipe.Id);
			if (!adapter.FetchEntity(recipeEntity))
				return Results.NotFound();

			// delete old recipe related entities
			adapter.FetchEntityCollection(recipeEntity.Ingredients, recipeEntity.GetRelationInfoIngredients());
			adapter.DeleteEntityCollection(recipeEntity.Ingredients);
			adapter.FetchEntityCollection(recipeEntity.Instructions, recipeEntity.GetRelationInfoInstructions());
			adapter.DeleteEntityCollection(recipeEntity.Instructions);
			adapter.FetchEntityCollection(recipeEntity.RecipeCategoryDictionaries, recipeEntity.GetRelationInfoRecipeCategoryDictionaries());
			adapter.DeleteEntityCollection(recipeEntity.RecipeCategoryDictionaries);

			// create instruction entities
			foreach (var instruction in editedRecipe.Instructions)
			{
				var instructionEntity = new InstructionEntity
				{
					Id = Guid.NewGuid(),
					Text = instruction,
					Recipe = recipeEntity
				};
			}

			// create ingredient entities
			foreach (var ingredient in editedRecipe.Ingredients)
			{
				var ingredientEntity = new IngredientEntity
				{
					Id = Guid.NewGuid(),
					Name = ingredient,
					Recipe = recipeEntity
				};
			}

			// create recipeCategoryDictionary entities
			foreach (var category in editedRecipe.Categories)
			{
				var categoryEntity = new CategoryEntity(category);
				if (!adapter.FetchEntity(categoryEntity))
					throw new Exception();

				var recipeCategoryDictionaryEntity = new RecipeCategoryDictionaryEntity()
				{
					Recipe = recipeEntity,
					Category = categoryEntity
				};
			}

			// Save all entities recursively
			if (!adapter.SaveEntity(recipeEntity))
				throw new Exception();
			adapter.Commit();
			return Results.Created($"/recipes/{editedRecipe.Id}", editedRecipe);
		}
		catch (Exception)
		{
			// Rollback if anything goes wrong
			adapter.Rollback();
			return Results.BadRequest();
		}
	}
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
			if (result)
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
			if (!adapter.FetchEntity(categoryEntity))
				return Results.NotFound();
			categoryEntity.IsActive = false;
			if (!adapter.SaveEntity(categoryEntity))
				throw new Exception("Could Not Save");
			return Results.Ok(category);
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
			if (!adapter.FetchEntity(categoryEntity))
				return Results.NotFound();
			categoryEntity.Name = editedCategory;
			if (!adapter.SaveEntity(categoryEntity))
				throw new Exception("Failed to save");
		}
		return Results.NoContent();
	}
	catch (Exception)
	{
		return Results.Problem();
	}
});

app.Run();