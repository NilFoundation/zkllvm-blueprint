
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Tatuzova Elena <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_LOOKUP_TABLE_LIBRARY_HPP
#define CRYPTO3_LOOKUP_TABLE_LIBRARY_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/detail/lookup_table_definition.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/assert.hpp>

namespace nil {
    namespace blueprint {
        template <typename Type, typename = void>
        struct component_use_lookup : std::false_type{ };

        template <typename Type>
        struct component_use_lookup<Type, 
            typename std::enable_if<std::is_member_function_pointer<decltype(&Type::component_lookup_tables)>::value>::type> : std::true_type
        { };

        template <typename Type>
        constexpr bool use_lookups(){
            if(component_use_lookup<Type>::value){
                return true;
            }
            return false;
        }

        template <typename Type, typename = void>
        struct component_use_custom_lookup_tables : std::false_type{ };

        template <typename Type>
        struct component_use_custom_lookup_tables<Type, 
            typename std::enable_if<std::is_member_function_pointer<decltype(&Type::component_custom_lookup_tables)>::value>::type> : std::true_type
        { };

        template <typename Type>
        constexpr bool use_custom_lookup_tables(){
            if(component_use_custom_lookup_tables<Type>::value){
                return true;
            }
            return false;
        }

        template <typename BlueprintFieldType>
        class lookup_table_library{
            using lookup_table_definition = typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
        protected:
            std::map<std::string, lookup_table_definition> tables;
            std::set<std::string> reserved_tables;
            std::map<std::string, std::size_t> reserved_tables_indices;
            std::map<std::string, lookup_table_definition> reserved_tables_map;
            // Last index
        public:
            lookup_table_library(){
                tables = {};
                tables["binary_xor_table"] = { "binary_xor_table", {
                    {0, 0, 1, 1},
                    {0, 1, 0, 1},
                    {0, 1, 1, 0}
                }, {} };
                tables["binary_xor_table"].subtables["full"] = {{0,1,2}, 0, 3};
            }
            
            void register_lookup_table(const lookup_table_definition &table){
                BOOST_ASSERT(tables.find(table.table_name) == tables.end());
                tables[table.table_name] = table;
            }

            void reserve_table(std::string name){
                std::string table_name = name.substr(0, name.find("/"));
                BOOST_ASSERT(tables.find(table_name) != tables.end());
                std::string subtable_name = name.substr(name.find("/")+1, name.size());
                BOOST_ASSERT(tables[table_name].subtables.find(subtable_name) != tables[table_name].subtables.end());
                reserved_tables.insert(name);
            }

            const std::map<std::string, std::size_t> &get_reserved_indices(){
                reserved_tables_indices = {};
                std::size_t i = 1;
                for (auto &name : reserved_tables){
                    reserved_tables_indices[name] = i;
                    i++;
                }
                return reserved_tables_indices;
            }

            const std::map<std::string, lookup_table_definition> &get_reserved_tables(){
                for (auto &name : reserved_tables){
                    std::string table_name = name.substr(0, name.find("/"));
                    BOOST_ASSERT(tables.find(table_name) != tables.end());
                    std::string subtable_name = name.substr(name.find("/")+1, name.size());
                    BOOST_ASSERT(tables[table_name].subtables.find(subtable_name) != tables[table_name].subtables.end());

                    if( reserved_tables_map.find(table_name) == reserved_tables_map.end() ){
                        reserved_tables_map[table_name].table_name = table_name;
                        reserved_tables_map[table_name].table = std::move(tables[table_name].table);
                    }
                    reserved_tables_map[table_name].subtables[subtable_name] = std::move(tables[table_name].subtables[subtable_name]);
                }
                return reserved_tables_map;
            }
        };
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_LOOKUP_TABLE_LIBRARY_HPP