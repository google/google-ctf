// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_EXAMPLES_JSON_CLASSES_HPP
#define TAOCPP_PEGTL_INCLUDE_EXAMPLES_JSON_CLASSES_HPP

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace examples
{
   enum class json_type
   {
      ARRAY,
      BOOLEAN,
      NULL_,
      NUMBER,
      OBJECT,
      STRING
   };

   class json_base
   {
   public:
      const json_type type;

      virtual void stream( std::ostream& ) const = 0;

   protected:
      explicit json_base( const json_type in_type )
         : type( in_type )
      {
      }

      ~json_base()
      {
      }
   };

   inline std::ostream& operator<<( std::ostream& o, const json_base& j )
   {
      j.stream( o );
      return o;
   }

   inline std::ostream& operator<<( std::ostream& o, const std::shared_ptr< json_base >& j )
   {
      return j ? ( o << *j ) : ( o << "NULL" );
   }

   struct array_json
      : public json_base
   {
      array_json()
         : json_base( json_type::ARRAY )
      {
      }

      std::vector< std::shared_ptr< json_base > > data;

      virtual void stream( std::ostream& o ) const override
      {
         o << '[';
         if( !data.empty() ) {
            auto iter = data.begin();
            o << *iter;
            while( ++iter != data.end() ) {
               o << ',' << *iter;
            }
         }
         o << ']';
      }
   };

   struct boolean_json
      : public json_base
   {
      explicit boolean_json( const bool in_data )
         : json_base( json_type::BOOLEAN ),
           data( in_data )
      {
      }

      bool data;

      virtual void stream( std::ostream& o ) const override
      {
         o << ( data ? "true" : "false" );
      }
   };

   struct null_json
      : public json_base
   {
      null_json()
         : json_base( json_type::NULL_ )
      {
      }

      virtual void stream( std::ostream& o ) const override
      {
         o << "null";
      }
   };

   struct number_json
      : public json_base
   {
      explicit number_json( const long double in_data )
         : json_base( json_type::NUMBER ),
           data( in_data )
      {
      }

      long double data;

      virtual void stream( std::ostream& o ) const override
      {
         o << data;
      }
   };

   inline std::string json_escape( const std::string& data )
   {
      std::string r = "\"";

      r.reserve( data.size() + 4 );

      static const char* h = "0123456789abcdef";

      const unsigned char* d = reinterpret_cast< const unsigned char* >( data.data() );

      for( std::size_t i = 0; i < data.size(); ++i ) {
         switch( const auto c = d[ i ] ) {
            case '\b':
               r += "\\b";
               break;
            case '\f':
               r += "\\f";
               break;
            case '\n':
               r += "\\n";
               break;
            case '\r':
               r += "\\r";
               break;
            case '\t':
               r += "\\t";
               break;
            case '\\':
               r += "\\\\";
               break;
            case '\"':
               r += "\\\"";
               break;
            default:
               if( ( c < 32 ) || ( c == 127 ) ) {
                  r += "\\u00";
                  r += h[ ( c & 0xf0 ) >> 4 ];
                  r += h[ c & 0x0f ];
                  continue;
               }
               r += c;  // Assume valid UTF-8.
               break;
         }
      }
      r += '"';
      return r;
   }

   struct string_json
      : public json_base
   {
      explicit string_json( const std::string& in_data )
         : json_base( json_type::STRING ),
           data( in_data )
      {
      }

      std::string data;

      virtual void stream( std::ostream& o ) const override
      {
         o << json_escape( data );
      }
   };

   struct object_json
      : public json_base
   {
      object_json()
         : json_base( json_type::OBJECT )
      {
      }

      std::map< std::string, std::shared_ptr< json_base > > data;

      virtual void stream( std::ostream& o ) const override
      {
         o << '{';
         if( !data.empty() ) {
            auto iter = data.begin();
            o << json_escape( iter->first ) << ':' << iter->second;
            while( ++iter != data.end() ) {
               o << ',' << json_escape( iter->first ) << ':' << iter->second;
            }
         }
         o << '}';
      }
   };

}  // examples

#endif
