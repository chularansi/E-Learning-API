using AutoMapper;
using E_Learning_API.Data.Entities;
using E_Learning_API.DTO;
using E_Learning_API.Extensions;
using E_Learning_API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace E_Learning_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class CategoriesController : ControllerBase
    {
        private readonly ICategoryRepository categoryRepository;
        private readonly IMapper mapper;

        public CategoriesController(ICategoryRepository categoryRepository, IMapper mapper)
        {
            this.categoryRepository = categoryRepository;
            this.mapper = mapper;
        }

        /// <summary>
        /// Get All Categories
        /// </summary>
        /// <returns>A list of Books</returns>
        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetCategories()
        {
            var errLocation = GetControllerAndActionNames();
            try
            {
                var categories = await categoryRepository.FindAll();
                var response = mapper.Map<IList<CategoryDTO>>(categories);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation}: {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// Get a Category by Id
        /// </summary>
        /// <param name="id"></param>
        /// <returns>A Book record</returns>
        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> GetCategory(int id)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                var category = await categoryRepository.FindById(id);
                if (category == null)
                {
                    return NotFound();
                }

                var response = mapper.Map<CategoryDTO>(category);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation} {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// Create a Category
        /// </summary>
        /// <param name="createCategoryDTO"></param>
        /// <returns>Book Object</returns>
        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Create([FromBody] CreateCategoryDTO createCategoryDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                if (createCategoryDTO == null || !ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                //if (!ModelState.IsValid)
                //{
                //    return BadRequest(ModelState);
                //}

                var category = mapper.Map<Category>(createCategoryDTO);
                category.UserId = Convert.ToInt32(HttpContext.GetUserId());
                var isSuccess = await categoryRepository.Create(category);
                if (!isSuccess)
                {
                    return ErrorHandler($"{errLocation} creation failed");
                }
                return Created("create", new { category });
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation} {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// Update a book
        /// </summary>
        /// <param name="id"></param>
        /// <param name="categoryDTO"></param>
        /// <returns></returns>
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Update(int id, [FromBody] CategoryDTO categoryDTO)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                if (id < 1 || categoryDTO == null || categoryDTO.Id != id)
                {
                    return BadRequest(ModelState);
                }

                var isExists = await categoryRepository.IsExists(id);
                if (!isExists)
                {
                    return NotFound();
                }

                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var category = mapper.Map<Category>(categoryDTO);
                category.UserId = Convert.ToInt32(HttpContext.GetUserId());
                var isSuccess = await categoryRepository.Update(category);
                if (!isSuccess)
                {
                    return ErrorHandler($"{errLocation} updation failed");
                }
                return NoContent();
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation} {ex.Message} - {ex.InnerException}");
            }
        }

        /// <summary>
        /// Remove a Category
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Delete(int id)
        {
            var errLocation = GetControllerAndActionNames();

            try
            {
                if (id < 1)
                {
                    return BadRequest();
                }

                var isExists = await categoryRepository.IsExists(id);
                if (!isExists)
                {
                    return NotFound();
                }

                var category = await categoryRepository.FindById(id);
                var isSuccess = await categoryRepository.Delete(category);
                if (!isSuccess)
                {
                    return ErrorHandler("Category delete failed");
                }

                return NoContent();
            }
            catch (Exception ex)
            {
                return ErrorHandler($"{errLocation} {ex.Message} - {ex.InnerException}");
            }
        }

        private ObjectResult ErrorHandler(string message)
        {
            //logger.LogError(message);
            return StatusCode(500, "Something went wrong, Please contact the Administrator");
        }

        private string GetControllerAndActionNames()
        {
            var controller = ControllerContext.ActionDescriptor.ControllerName;
            var action = ControllerContext.ActionDescriptor.ActionName;

            return $"{controller} - {action}";
        }
    }
}
