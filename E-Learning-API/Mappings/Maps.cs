using AutoMapper;
using DataService.Models;
using E_Learning_API.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace E_Learning_API.Mappings
{
    public class Maps : Profile
    {
        public Maps()
        {
            CreateMap<Category, CategoryDTO>().ReverseMap();
            //CreateMap<Category, CreateCategoryDTO>().ReverseMap();
            //CreateMap<Author, AuthorUpdateDTO>().ReverseMap();
            //CreateMap<Book, BookDTO>().ReverseMap();
            //CreateMap<Book, BookCreateDTO>().ReverseMap();
            //CreateMap<Book, BookUpdateDTO>().ReverseMap();
        }
    }
}
