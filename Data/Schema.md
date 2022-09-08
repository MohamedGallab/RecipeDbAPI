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
	- Guid RecipeId (Fk)(Pk)
	- String CategoryName (Fk)(Pk)
- Instruction
	- String Step
	- Guid RecipeId (Fk)
- Ingredient
	- String Component
	- Guid RecipeId (Fk)