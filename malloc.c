

static short check_mem_type_init();
static void *create_new_space(int);
static void *walk_in_list(int);
static void zeroed(char(*), int);

void *avr_malloc(int);
short free_mem(void(*));

extern char *__heap_start; //  from avr-gcc generated
extern char *__heap_end;   //  from avr-gcc generated

extern char *__brkval; // end of .data section

struct memory_type
{
    int mem_size;
    short inuse;
    struct memory_type(*next_mem_ptr);
} __attribute__((packed)); // we dont want memory alignment

static struct memory_type(*head_mem_ptr) = ((void *)0);

void *avr_malloc(int size)
{
    if (check_mem_type_init())
        return walk_in_list(size);
    return create_new_space(size);
}

static void *
create_new_space(int size)
{
    if (__brkval == 0)
        __brkval = __heap_start; // set default address to __heap_start symbol address from avr-gcc
    // check pre-process
    int remains_heap = __heap_end - __brkval;
    if ((__heap_end <= __brkval) || (remains_heap <= size) || (*__heap_end <= (size + *__brkval)))
    {
        // Memory exhausted or no memory left or over request memory from remains SRAM.
        // no diff error returns, just nullptr
        return ((void *)0);
    }
    // memory assignment (core malloc)
    struct memory_type(*curr_mem_addr) = (struct memory_type(*))__brkval + size;
    curr_mem_addr->mem_size = size;
    curr_mem_addr->inuse = 1;

    if (head_mem_ptr) // has list?
    {
        curr_mem_addr->next_mem_ptr = head_mem_ptr;
    }
    else // nope
    {
        curr_mem_addr->next_mem_ptr = ((void *)0); // NULL
    }
    head_mem_ptr = curr_mem_addr;
    __brkval = __brkval + size + sizeof(int) + sizeof(short) + sizeof(struct memory_type(*));
    void(*ret_ptr) = (void(*))curr_mem_addr + sizeof(int) + sizeof(short) + sizeof(struct memory_type(*)); // avoid override
    zeroed((char(*))ret_ptr, size);
    return ret_ptr;
}

static void zeroed(char(*ret_ptr), int size) // we dont want overflow type boundry, we need char
{
    int index = 0;
    while (index < size)
    {
        *(ret_ptr) = 0;
        index++;
    }
}

static void *
walk_in_list(int size)
{
    struct memory_type *walk_mem_ptr;
    // look for freed memory_type with fit size, so we dont need to create new space.
    for (walk_mem_ptr = head_mem_ptr; walk_mem_ptr != ((void *)0); walk_mem_ptr = walk_mem_ptr->next_mem_ptr)
    {
        if (!walk_mem_ptr->inuse && walk_mem_ptr->mem_size >= size)
        { // found it, update mem_type with used and return it.
            int remaining_size = walk_mem_ptr->mem_size - size;
            struct memory_type *baby_mem_addr = (struct memory_type *)(walk_mem_ptr + remaining_size);
            baby_mem_addr->mem_size = remaining_size;
            baby_mem_addr->inuse = 0;
            baby_mem_addr->next_mem_ptr = walk_mem_ptr;
            // OK TOO : baby_mem_addr->next_mem_ptr = walk_mem_ptr->next_mem_ptr;
            // OK TOO : walk_mem_ptr->next_mem_ptr = baby_mem_addr;
            if (walk_mem_ptr == head_mem_ptr)
            {
                head_mem_ptr = baby_mem_addr;
            }
            walk_mem_ptr->mem_size = size;
            walk_mem_ptr->inuse = 1;
            void(*ret_ptr) = (void(*))walk_mem_ptr + sizeof(int) + sizeof(short) + sizeof(struct memory_type(*)); // avoid override
            zeroed((char(*))ret_ptr, size);
            return ret_ptr;
        }
    }
    return create_new_space(size); // not found, create new space
}

static short check_mem_type_init()
{
    if (head_mem_ptr != ((void *)0)) // is it your first time? ;)
        return 1;
    return 0;
}

short free_mem(void *addr)
{
    if (addr == (void(*))0)
        return 0;

    struct memory_type *walk_mem_ptr;
    for (walk_mem_ptr = head_mem_ptr; walk_mem_ptr != ((void *)0); walk_mem_ptr = walk_mem_ptr->next_mem_ptr)
    {
        if (walk_mem_ptr == (struct memory_type *)addr)
        { // found it, update memory type & combine next memory type if that also freed
            // NOTE : no need to update __brkval, we ll walk in list for future requests.
            walk_mem_ptr->inuse = 0;
            if (walk_mem_ptr->next_mem_ptr != ((void *)0) && walk_mem_ptr->next_mem_ptr->inuse == 0)
            { // merge sizes for avoid fragmentation
                int merge_size = walk_mem_ptr->mem_size + walk_mem_ptr->next_mem_ptr->mem_size;
                walk_mem_ptr->mem_size = merge_size;
                walk_mem_ptr->next_mem_ptr = walk_mem_ptr->next_mem_ptr->next_mem_ptr;
            }
            return 1;
        }
    }
    return 0;
}