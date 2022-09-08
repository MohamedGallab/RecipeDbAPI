## Db Schema
Tables:
- Recipe


	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| Guid | Id | Primary Key |
	| String | Title | |
- User
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| String | Username | Primary Key |
	| String | Password | |
	| String | RefreshToken | |
- Category
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| String | Name | Primary Key |
- RecipeCategoryDictionary
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| Guid | RecipeId | Composite Primary Key, Foreign references Recipe.Id |
	| String | CategoryName | Composite Primary Key, Foreign references Category.Name |
- Instruction
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| String | Step | |
	| Guid | RecipeId | Foreign references Recipe.Id |
- Ingredient
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| String | Component | |
	| Guid | RecipeId | Foreign references Recipe.Id |


Relationships:

| Type | Tables involved 
| --- | --- |
| One to Many | Recipe to instructions |
| One to Many | Recipe to Ingredients |
| Many to Many | Recipes to Categories | 

