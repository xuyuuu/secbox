#ifndef sec_box_ring_h
#define sec_box_ring_h

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define SEC_BOX_RING_X86_ALIGN_SIZE 64
#define SEC_BOX_RING_X86_ALIGN_MASK (SEC_BOX_RING_X86_ALIGN_SIZE - 1)

#define SEC_BOX_RING_COMPILER_BARRIER() do {\
	        asm volatile ("" : : : "memory");\
} while(0)

typedef struct sec_box_ring sec_box_ring_t;

struct sec_box_ring_module
{
	sec_box_ring_t *(* create)(uint32_t nem);
	int (* enqueue)(sec_box_ring_t *ring, void *item);
	int (* dequeue)(sec_box_ring_t *ring, void **item);
	int (* destroy)(void);
}__attribute__((packed));


struct sec_box_ring
{
	/*sec_box_ring producer status*/
	struct producer
	{
		uint32_t watermark;
		uint32_t sp_enqueue;
		uint32_t size;
		uint32_t mask;

		volatile uint32_t head;
		volatile uint32_t tail;
	}prod __attribute__((__aligned__(64)));

	/*sec_box_ring consumer status */
	struct consumer
	{
		uint32_t sc_dequeue;	
		uint32_t size;
		uint32_t mask;

		volatile uint32_t head;
		volatile uint32_t tail;
	}cons __attribute__((__aligned__(64)));

	void *ring[0];
}__attribute__((packed));

extern struct sec_box_ring_module sec_box_ring_module;

#endif

