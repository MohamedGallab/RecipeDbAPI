## Db Schema
Tables:
- Recipe


	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| Guid | Id | Primary Key |
	| String | Title | Not Null |
- User
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| String | Username | Primary Key |
	| String | Password | Not Null |
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
	| Guid | Id | Primary Key |
	| String | Step | Not Null |
	| Guid | RecipeId | Foreign references Recipe.Id |
- Ingredient
	| Field Type | Field Name | Notes
	| --- | --- | --- |
	| Guid | Id | Primary Key |
	| String | Component | Not Null |
	| Guid | RecipeId | Foreign references Recipe.Id |


Relationships:

| Type | Tables involved 
| --- | --- |
| One to Many | Recipe to instructions |
| One to Many | Recipe to Ingredients |
| Many to Many | Recipes to Categories | 

