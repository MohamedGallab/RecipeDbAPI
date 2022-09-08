## Db Schema
Tables:
- Recipe
	- Guid Id (Pk)
	- String Title
- User
	- String Username (Pk)
	- String Password
	- String RefreshToken
- Categories
	- String Name (Pk)
- RecipeCategoryDictionary
	- Guid RecipeId (Fk references Recipe.Id)(Pk)
	- String CategoryName (Fk references Category.Name)(Pk)
- Instruction
	- String Step
	- Guid RecipeId (Fk references Recipe.Id)
- Ingredient
	- String Component
	- Guid RecipeId (Fk references Recipe.Id)


Relations:
- One recipe has many instructions
- One recipe has many Iingredients
- many to many relation between recipes and categories
