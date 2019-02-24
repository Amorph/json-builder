
/* vim: set et ts=3 sw=3 sts=3 ft=c:
 *
 * Copyright (C) 2014 James McLaughlin.  All rights reserved.
 * https://github.com/udp/json-builder
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "json-builder.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>

#ifdef _MSC_VER
    #define snprintf _snprintf
#endif

static const json_serialize_opts default_opts =
{
   json_serialize_mode_single_line,
   0,
   3  /* indent_size */
};
static void * default_alloc(size_t size, int zero, void * user_data)
{
	return zero ? calloc(1, size) : malloc(size);
}

static void default_free(void * ptr, void * user_data)
{
	free(ptr);
}

static void * json_builder_alloc (json_builder_state * state, unsigned long size, int zero)
{
	if(state->settings.mem_alloc)
		return state->settings.mem_alloc (size, zero, state->settings.user_data);
	return default_alloc(size, zero, state->settings.user_data);
}

static void json_builder_free (json_builder_state * state, void * block)
{
	if (state->settings.mem_free)
		state->settings.mem_free (block, state->settings.user_data);
	else
		default_free (block, state->settings.user_data);
}

static void * json_builder_realloc (json_builder_state * state, void * block, unsigned long old_size, unsigned long size)
{
  void * new_block = json_builder_alloc (state, size, 0);

  memcpy (new_block, block, old_size);
  json_builder_free (state, block);

  return new_block;
}

typedef struct json_builder_value
{
   json_value value;

   size_t length_iterated;

} json_builder_value;

const size_t json_builder_extra = sizeof(json_builder_value) - sizeof(json_value);

/* These flags are set up from the opts before serializing to make the
 * serializer conditions simpler.
 */
const int f_spaces_around_brackets = (1 << 0);
const int f_spaces_after_commas    = (1 << 1);
const int f_spaces_after_colons    = (1 << 2);
const int f_tabs                   = (1 << 3);

static int get_serialize_flags (json_serialize_opts opts)
{
   int flags = 0;

   if (opts.mode == json_serialize_mode_packed)
      return 0;

   if (opts.mode == json_serialize_mode_multiline)
   {
      if (opts.opts & json_serialize_opt_use_tabs)
         flags |= f_tabs;
   }
   else
   {
      if (! (opts.opts & json_serialize_opt_pack_brackets))
         flags |= f_spaces_around_brackets;

      if (! (opts.opts & json_serialize_opt_no_space_after_comma))
         flags |= f_spaces_after_commas;
   }

   if (! (opts.opts & json_serialize_opt_no_space_after_colon))
      flags |= f_spaces_after_colons;

   return flags;
}

json_value * json_array_new (json_builder_state * state)
{
    json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 1);

    if (!value)
       return NULL;

    value->type = json_array;

    if (! (value->u.array.values = (json_value **) json_builder_alloc (state, 0 * sizeof (json_value *), 0)))
    {
	   json_builder_free (state, value);
       return NULL;
    }

    return value;
}

json_value * json_array_push (json_builder_state * state, json_value * array, json_value * value)
{
   assert (array->type == json_array);

    json_value ** values_new = (json_value **) json_builder_realloc
        (state,
    array->u.array.values, 
    sizeof (json_value *) * (array->u.array.length),
    sizeof (json_value *) * (array->u.array.length + 1));

    if (!values_new)
        return NULL;

    array->u.array.values = values_new;

   array->u.array.values [array->u.array.length] = value;
   ++ array->u.array.length;

   value->parent = array;

   return value;
}

json_value * json_array_del(json_builder_state * state, json_value * array, unsigned int i)
{
	assert(array->type == json_array);
	assert(array->u.array.length > i);

	json_value ** values_new = (json_value **) json_builder_alloc(state, sizeof(json_value *) * (array->u.array.length - 1), 0);
	if (!values_new)
		return NULL;

	unsigned int before = i;
	unsigned int after = array->u.array.length - i - 1;
	if(before)
		memcpy(values_new, array->u.array.values, sizeof(json_value *) * before);
	if (after)
		memcpy(values_new + before, array->u.array.values + i + 1, sizeof(json_value *) * after);
	
	json_value* deleted = array->u.array.values[i];
	deleted->parent = NULL;
	json_builder_free(state, array->u.array.values);
	array->u.array.values = values_new;
	array->u.array.length--;

	return deleted;
}

json_value * json_object_new (json_builder_state * state)
{
    json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 1);

    if (!value)
       return NULL;

    value->type = json_object;

    if (! (value->u.object.values = (json_object_entry *) json_builder_alloc
           (state, 0 * sizeof (*value->u.object.values), 1)))
    {
       json_builder_free (state, value);
       return NULL;
    }

    return value;
}

json_value * json_object_push (json_builder_state * state, 
                               json_value * object,
                               const json_char * name,
                               json_value * value)
{
   return json_object_push_length (state, object, strlen (name), name, value);
}

unsigned long compute_json_object_values_mem_size(json_value * object)
{
	unsigned long size = sizeof(*object->u.object.values) * object->u.object.length;
	for (unsigned int i = 0; i < object->u.object.length; i++)
	{
		size += object->u.object.values[i].name_length + 1;
	}
	return size;
}

json_value * json_object_push_length (json_builder_state * state, 
                                      json_value * object,
                                      unsigned int name_length, const json_char * name,
                                      json_value * value)
{
   json_char * name_copy;

   assert (object->type == json_object);

   unsigned long old_mem_size = compute_json_object_values_mem_size(object);
   unsigned long new_mem_size = old_mem_size + sizeof(*object->u.object.values) + (name_length + 1) * sizeof(json_char);

   json_object_entry * new_values = (json_object_entry *)json_builder_alloc(state, new_mem_size, 0);
   json_char* new_data = (json_char *)(new_values + object->u.object.length + 1);

   // Copy old value tables
   for (unsigned int i = 0; i < object->u.object.length; i++)
   {
	   new_values[i].name_length = object->u.object.values[i].name_length;
	   new_values[i].value = object->u.object.values[i].value;
	   new_values[i].name = new_data;
	   memcpy(new_data, object->u.object.values[i].name, new_values[i].name_length + 1);
	   new_data += new_values[i].name_length + 1;
   }
   // Create a new record
   json_object_entry * entry = new_values + object->u.object.length;

   entry->name_length = name_length;
   entry->name = new_data;
   entry->value = value;
   
   memcpy(new_data, name, name_length);
   new_data[name_length] = 0;
   new_data += name_length + 1;
   assert(new_data == ((json_char*)new_values) + new_mem_size);
   json_builder_free(state, object->u.object.values);
   object->u.object.values = new_values;
   object->u.object.length++;

   value->parent = object;

   return value;
}

json_value * json_object_del (json_builder_state * state, 
                                      json_value * object,
                                      unsigned int index)
{
   json_char * name_copy;

   assert (object->type == json_object);
   assert (object->u.object.length > index);

   unsigned long old_mem_size = compute_json_object_values_mem_size(object);
   unsigned long new_mem_size = old_mem_size - sizeof(*object->u.object.values) - (object->u.object.values[index].name_length + 1) * sizeof(json_char);

   json_object_entry * new_values = (json_object_entry *)json_builder_alloc(state, new_mem_size, 0);
   json_char* new_data = (json_char *)(new_values + object->u.object.length - 1);

   // Copy old value tables
   for (unsigned int i = 0, new_i = 0; i < object->u.object.length; i++)
   {
	   if (i == index)
		   continue;

	   new_values[new_i].name_length = object->u.object.values[i].name_length;
	   new_values[new_i].value = object->u.object.values[i].value;
	   new_values[new_i].name = new_data;
	   memcpy(new_data, object->u.object.values[i].name, new_values[new_i].name_length + 1);
	   new_data += new_values[new_i].name_length + 1;

	   new_i++;
   }
   assert(new_data == ((json_char*)new_values) + new_mem_size);
   json_value * deleted = object->u.object.values[index].value;
   
   json_builder_free(state, object->u.object.values);
   object->u.object.values = new_values;
   object->u.object.length--;

   deleted->parent = NULL;

   return deleted;
}

json_value * json_string_new (json_builder_state * state, const json_char * buf)
{
   return json_string_new_length (state, strlen (buf), buf);
}

json_value * json_string_new_length (json_builder_state * state, unsigned int length, const json_char * buf)
{
	json_value * value = (json_value *)json_builder_alloc(state, sizeof(json_builder_value), 1);
   
   if (!value)
      return NULL;

   json_char * copy = (json_char  *)json_builder_alloc(state, (length + 1) * sizeof(json_char), 0);
   if (!copy)
   {
	   json_builder_free(state, value);
	   return NULL;
   }

   value->type = json_string;
   value->u.string.length = length;
   value->u.string.ptr = copy;
   
   memcpy (copy, buf, length * sizeof (json_char));
   copy [length] = 0;

   return value;
}

json_value * json_integer_new (json_builder_state * state, json_int_t integer)
{
   json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 0);
   
   if (!value)
      return NULL;

   value->type = json_integer;
   value->u.integer = integer;

   return value;
}

json_value * json_double_new (json_builder_state * state, double dbl)
{
   json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 1);
   
   if (!value)
      return NULL;

   value->type = json_double;
   value->u.dbl = dbl;

   return value;
}

json_value * json_boolean_new (json_builder_state * state, int b)
{
   json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 1);
   
   if (!value)
      return NULL;

   value->type = json_boolean;
   value->u.boolean = b;

   return value;
}

json_value * json_null_new (json_builder_state * state)
{
   json_value * value = (json_value *) json_builder_alloc (state, sizeof (json_builder_value), 1);
   
   if (!value)
      return NULL;

   value->type = json_null;

   return value;
}

void json_object_sort (json_builder_state * state, json_value * object, json_value * proto)
{
	// TODO add support
	/*
   unsigned int i, out_index = 0;

   assert (object->type == json_object);
   assert (proto->type == json_object);

   for (i = 0; i < proto->u.object.length; ++ i)
   {
      unsigned int j;
      json_object_entry proto_entry = proto->u.object.values [i];

      for (j = 0; j < object->u.object.length; ++ j)
      {
         json_object_entry entry = object->u.object.values [j];

         if (entry.name_length != proto_entry.name_length)
            continue;

         if (memcmp (entry.name, proto_entry.name, entry.name_length) != 0)
            continue;

         object->u.object.values [j] = object->u.object.values [out_index];
         object->u.object.values [out_index] = entry;

         ++ out_index;
      }
   }*/
}

json_value * json_object_merge (json_builder_state * state, json_value * objectA, json_value * objectB)
{
	// TODO add support
	return NULL;
	/*
   unsigned int i;

   assert (objectA->type == json_object);
   assert (objectB->type == json_object);
   assert (objectA != objectB);

   if (!builderize (state, objectA) || !builderize (state, objectB))
      return NULL;

   if (objectB->u.object.length <=
        ((json_builder_value *) objectA)->additional_length_allocated)
   {
      ((json_builder_value *) objectA)->additional_length_allocated
          -= objectB->u.object.length;
   }
   else
   {
      json_object_entry * values_new;

    unsigned int source_size = objectA->u.object.length
      + ((json_builder_value *) objectA)->additional_length_allocated;

      unsigned int alloc = source_size + objectB->u.object.length;

      if (! (values_new = (json_object_entry *)
            json_builder_realloc (state,
        objectA->u.object.values, 
        sizeof (json_object_entry) * source_size,
        sizeof (json_object_entry) * alloc)))
      {
          return NULL;
      }

      objectA->u.object.values = values_new;
   }

   for (i = 0; i < objectB->u.object.length; ++ i)
   {
      json_object_entry * entry = &objectA->u.object.values[objectA->u.object.length + i];

      *entry = objectB->u.object.values[i];
      entry->value->parent = objectA;
   }

   objectA->u.object.length += objectB->u.object.length;

   json_builder_free (state, objectB->u.object.values);
   json_builder_free (state, objectB);
   */
   return objectA;
}

static size_t measure_string (unsigned int length,
                              const json_char * str)
{
   unsigned int i;
   size_t measured_length = 0;

   for(i = 0; i < length; ++ i)
   {
      json_char c = str [i];

      switch (c)
      {
      case '"':
      case '\\':
      case '\b':
      case '\f':
      case '\n':
      case '\r':
      case '\t':

         measured_length += 2;
         break;

      default:

         ++ measured_length;
         break;
      };
   };

   return measured_length;
}

#define PRINT_ESCAPED(c) do {  \
   *buf ++ = '\\';             \
   *buf ++ = (c);              \
} while(0);                    \

static size_t serialize_string (json_char * buf,
                                unsigned int length,
                                const json_char * str)
{
   json_char * orig_buf = buf;
   unsigned int i;

   for(i = 0; i < length; ++ i)
   {
      json_char c = str [i];

      switch (c)
      {
      case '"':   PRINT_ESCAPED ('\"');  continue;
      case '\\':  PRINT_ESCAPED ('\\');  continue;
      case '\b':  PRINT_ESCAPED ('b');   continue;
      case '\f':  PRINT_ESCAPED ('f');   continue;
      case '\n':  PRINT_ESCAPED ('n');   continue;
      case '\r':  PRINT_ESCAPED ('r');   continue;
      case '\t':  PRINT_ESCAPED ('t');   continue;

      default:

         *buf ++ = c;
         break;
      };
   };

   return buf - orig_buf;
}

size_t json_measure (json_value * value)
{
   return json_measure_ex (value, default_opts);
}

#define MEASURE_NEWLINE() do {                     \
   ++ newlines;                                    \
   indents += depth;                               \
} while(0);                                        \

size_t json_measure_ex (json_value * value, json_serialize_opts opts)
{
   size_t total = 1;  /* null terminator */
   size_t newlines = 0;
   size_t depth = 0;
   size_t indents = 0;
   int flags;
   int bracket_size, comma_size, colon_size;

   flags = get_serialize_flags (opts);

   /* to reduce branching
    */
   bracket_size = flags & f_spaces_around_brackets ? 2 : 1;
   comma_size = flags & f_spaces_after_commas ? 2 : 1;
   colon_size = flags & f_spaces_after_colons ? 2 : 1;

   while (value)
   {
      json_int_t integer;
      json_object_entry * entry;

      switch (value->type)
      {
         case json_array:

            if (((json_builder_value *) value)->length_iterated == 0)
            {
               if (value->u.array.length == 0)
               {
                  total += 2;  /* `[]` */
                  break;
               }

               total += bracket_size;  /* `[` */

               ++ depth;
               MEASURE_NEWLINE(); /* \n after [ */
            }

            if (((json_builder_value *) value)->length_iterated == value->u.array.length)
            {
               -- depth;
               MEASURE_NEWLINE();
               total += bracket_size;  /* `]` */

               ((json_builder_value *) value)->length_iterated = 0;
               break;
            }

            if (((json_builder_value *) value)->length_iterated > 0)
            {
               total += comma_size;  /* `, ` */

               MEASURE_NEWLINE();
            }

            ((json_builder_value *) value)->length_iterated++;
            value = value->u.array.values [((json_builder_value *) value)->length_iterated - 1];
            continue;

         case json_object:

            if (((json_builder_value *) value)->length_iterated == 0)
            {
               if (value->u.object.length == 0)
               {
                  total += 2;  /* `{}` */
                  break;
               }

               total += bracket_size;  /* `{` */

               ++ depth;
               MEASURE_NEWLINE(); /* \n after { */
            }

            if (((json_builder_value *) value)->length_iterated == value->u.object.length)
            {
               -- depth;
               MEASURE_NEWLINE();
               total += bracket_size;  /* `}` */

               ((json_builder_value *) value)->length_iterated = 0;
               break;
            }

            if (((json_builder_value *) value)->length_iterated > 0)
            {
               total += comma_size;  /* `, ` */
               MEASURE_NEWLINE();
            }

            entry = value->u.object.values + (((json_builder_value *) value)->length_iterated ++);

            total += 2 + colon_size;  /* `"": ` */
            total += measure_string (entry->name_length, entry->name);

            value = entry->value;
            continue;

         case json_string:

            total += 2;  /* `""` */
            total += measure_string (value->u.string.length, value->u.string.ptr);
            break;

         case json_integer:

            integer = value->u.integer;

            if (integer < 0)
            {
               total += 1;  /* `-` */
               integer = - integer;
            }

            ++ total;  /* first digit */

            while (integer >= 10)
            {
               ++ total;  /* another digit */
               integer /= 10;
            }

            break;

         case json_double:

            total += snprintf (NULL, 0, "%g", value->u.dbl);

            /* Because sometimes we need to add ".0" if sprintf does not do it
             * for us. Downside is that we allocate more bytes than strictly
             * needed for serialization.
             */
            total += 2;

            break;

         case json_boolean:

            total += value->u.boolean ? 
               4:  /* `true` */
               5;  /* `false` */

            break;

         case json_null:

            total += 4;  /* `null` */
            break;

         default:
            break;
      };

      value = value->parent;
   }

   if (opts.mode == json_serialize_mode_multiline)
   {
      total += newlines * (((opts.opts & json_serialize_opt_CRLF) ? 2 : 1));
      total += indents * opts.indent_size;
   }

   return total;
}

void json_serialize (json_char * buf, json_value * value)
{
   json_serialize_ex (buf, value, default_opts);
}

#define PRINT_NEWLINE() do {                          \
   if (opts.mode == json_serialize_mode_multiline) {  \
      if (opts.opts & json_serialize_opt_CRLF)        \
         *buf ++ = '\r';                              \
      *buf ++ = '\n';                                 \
      for(i = 0; i < indent; ++ i)                    \
         *buf ++ = indent_char;                       \
   }                                                  \
} while(0);                                           \

#define PRINT_OPENING_BRACKET(c) do {                 \
   *buf ++ = (c);                                     \
   if (flags & f_spaces_around_brackets)              \
      *buf ++ = ' ';                                  \
} while(0);                                           \

#define PRINT_CLOSING_BRACKET(c) do {                 \
   if (flags & f_spaces_around_brackets)              \
      *buf ++ = ' ';                                  \
   *buf ++ = (c);                                     \
} while(0);                                           \

void json_serialize_ex (json_char * buf, json_value * value, json_serialize_opts opts)
{
   json_int_t integer, orig_integer;
   json_object_entry * entry;
   json_char * ptr, * dot;
   int indent = 0;
   char indent_char;
   int i;
   int flags;

   flags = get_serialize_flags (opts);

   indent_char = flags & f_tabs ? '\t' : ' ';

   while (value)
   {
      switch (value->type)
      {
         case json_array:

            if (((json_builder_value *) value)->length_iterated == 0)
            {
               if (value->u.array.length == 0)
               {
                  *buf ++ = '[';
                  *buf ++ = ']';

                  break;
               }

               PRINT_OPENING_BRACKET ('[');

               indent += opts.indent_size;
               PRINT_NEWLINE();
            }

            if (((json_builder_value *) value)->length_iterated == value->u.array.length)
            {
               indent -= opts.indent_size;
               PRINT_NEWLINE();
               PRINT_CLOSING_BRACKET (']');

               ((json_builder_value *) value)->length_iterated = 0;
               break;
            }

            if (((json_builder_value *) value)->length_iterated > 0)
            {
               *buf ++ = ',';

               if (flags & f_spaces_after_commas)
                  *buf ++ = ' ';

               PRINT_NEWLINE();
            }

            ((json_builder_value *) value)->length_iterated++;
            value = value->u.array.values [((json_builder_value *) value)->length_iterated - 1];
            continue;

         case json_object:

            if (((json_builder_value *) value)->length_iterated == 0)
            {
               if (value->u.object.length == 0)
               {
                  *buf ++ = '{';
                  *buf ++ = '}';

                  break;
               }

               PRINT_OPENING_BRACKET ('{');

               indent += opts.indent_size;
               PRINT_NEWLINE();
            }

            if (((json_builder_value *) value)->length_iterated == value->u.object.length)
            {
               indent -= opts.indent_size;
               PRINT_NEWLINE();
               PRINT_CLOSING_BRACKET ('}');

               ((json_builder_value *) value)->length_iterated = 0;
               break;
            }

            if (((json_builder_value *) value)->length_iterated > 0)
            {
               *buf ++ = ',';

               if (flags & f_spaces_after_commas)
                  *buf ++ = ' ';

               PRINT_NEWLINE();
            }

            entry = value->u.object.values + (((json_builder_value *) value)->length_iterated ++);

            *buf ++ = '\"';
            buf += serialize_string (buf, entry->name_length, entry->name);
            *buf ++ = '\"';
            *buf ++ = ':';

            if (flags & f_spaces_after_colons)
               *buf ++ = ' ';

            value = entry->value;
            continue;

         case json_string:

            *buf ++ = '\"';
            buf += serialize_string (buf, value->u.string.length, value->u.string.ptr);
            *buf ++ = '\"';
            break;

         case json_integer:

            integer = value->u.integer;

            if (integer < 0)
            {
               *buf ++ = '-';
               integer = - integer;
            }

            orig_integer = integer;

            ++ buf;

            while (integer >= 10)
            {
               ++ buf;
               integer /= 10;
            }

            integer = orig_integer;
            ptr = buf;

            do
            {
               *-- ptr = "0123456789"[integer % 10];

            } while ((integer /= 10) > 0);

            break;

         case json_double:

            ptr = buf;

            buf += sprintf (buf, "%g", value->u.dbl);

            if ((dot = strchr (ptr, ',')))
            {
               *dot = '.';
            }
            else if (!strchr (ptr, '.') && !strchr (ptr, 'e'))
            {
               *buf ++ = '.';
               *buf ++ = '0';
            }

            break;

         case json_boolean:

            if (value->u.boolean)
            {
               memcpy (buf, "true", 4);
               buf += 4;
            }
            else
            {
               memcpy (buf, "false", 5);
               buf += 5;
            }

            break;

         case json_null:

            memcpy (buf, "null", 4);
            buf += 4;
            break;

         default:
            break;
      };

      value = value->parent;
   }

   *buf = 0;
}
