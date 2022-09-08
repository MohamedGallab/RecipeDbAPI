﻿//////////////////////////////////////////////////////////////
// <auto-generated>This code was generated by LLBLGen Pro 5.9.</auto-generated>
//////////////////////////////////////////////////////////////
// Code is generated on: 
// Code is generated using templates: SD.TemplateBindings.SharedTemplates
// Templates vendor: Solutions Design.
//////////////////////////////////////////////////////////////
using System;
using SD.LLBLGen.Pro.ORMSupportClasses;

namespace RecipeDB.HelperClasses
{
	/// <summary>Field Creation Class for entity CategoryEntity</summary>
	public partial class CategoryFields
	{
		/// <summary>Creates a new CategoryEntity.Name field instance</summary>
		public static EntityField2 Name { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(CategoryFieldIndex.Name); }}
	}

	/// <summary>Field Creation Class for entity IngredientEntity</summary>
	public partial class IngredientFields
	{
		/// <summary>Creates a new IngredientEntity.Component field instance</summary>
		public static EntityField2 Component { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(IngredientFieldIndex.Component); }}
		/// <summary>Creates a new IngredientEntity.RecipeId field instance</summary>
		public static EntityField2 RecipeId { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(IngredientFieldIndex.RecipeId); }}
	}

	/// <summary>Field Creation Class for entity InstructionEntity</summary>
	public partial class InstructionFields
	{
		/// <summary>Creates a new InstructionEntity.RecipeId field instance</summary>
		public static EntityField2 RecipeId { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(InstructionFieldIndex.RecipeId); }}
		/// <summary>Creates a new InstructionEntity.Step field instance</summary>
		public static EntityField2 Step { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(InstructionFieldIndex.Step); }}
	}

	/// <summary>Field Creation Class for entity RecipeEntity</summary>
	public partial class RecipeFields
	{
		/// <summary>Creates a new RecipeEntity.Id field instance</summary>
		public static EntityField2 Id { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(RecipeFieldIndex.Id); }}
		/// <summary>Creates a new RecipeEntity.Title field instance</summary>
		public static EntityField2 Title { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(RecipeFieldIndex.Title); }}
	}

	/// <summary>Field Creation Class for entity RecipeCategoryDictionaryEntity</summary>
	public partial class RecipeCategoryDictionaryFields
	{
		/// <summary>Creates a new RecipeCategoryDictionaryEntity.CategoryName field instance</summary>
		public static EntityField2 CategoryName { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(RecipeCategoryDictionaryFieldIndex.CategoryName); }}
		/// <summary>Creates a new RecipeCategoryDictionaryEntity.RecipeId field instance</summary>
		public static EntityField2 RecipeId { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(RecipeCategoryDictionaryFieldIndex.RecipeId); }}
	}

	/// <summary>Field Creation Class for entity UserEntity</summary>
	public partial class UserFields
	{
		/// <summary>Creates a new UserEntity.Password field instance</summary>
		public static EntityField2 Password { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(UserFieldIndex.Password); }}
		/// <summary>Creates a new UserEntity.RefreshToken field instance</summary>
		public static EntityField2 RefreshToken { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(UserFieldIndex.RefreshToken); }}
		/// <summary>Creates a new UserEntity.Username field instance</summary>
		public static EntityField2 Username { get { return ModelInfoProviderSingleton.GetInstance().CreateField2(UserFieldIndex.Username); }}
	}
	

}