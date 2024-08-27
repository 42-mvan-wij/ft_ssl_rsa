NAME := ft_ssl

SRCDIR := src
SOURCES := $(shell find $(SRCDIR) -name '*.c' -not -name '*_bonus.c' -not -name '128*')
OBJDIR := obj
OBJECTS := $(addprefix $(OBJDIR)/, $(SOURCES:c=o))

# ifdef BONUS
# OBJECTS += $(OBJECTS_BONUS)
# endif

CFLAGS := -Wall -Wextra -Werror
ifdef NO_WARN
	CFLAGS :=
endif
LFLAGS := 
ifdef DEBUG
	CFLAGS += -g -fsanitize=address,undefined,leak,unsigned-integer-overflow
	LFLAGS += -g -fsanitize=address,undefined,leak
endif

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJECTS)
	$(CC) $(LFLAGS) $(OBJECTS) -o $@

.GOAL: all
.PHONY: all
all: $(NAME)

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

.PHONY: fclean
fclean: clean
	rm -f $(NAME)
	# rm -f $(TEST_NAME)

.PHONY: re
re: fclean all

.PHONY: bonus
bonus:
	$(MAKE) BONUS=1

.PHONY: re_bonus
re_bonus:
	$(MAKE) BONUS=1 re

# .PHONY: test
# test: all
# ifdef BONUS
# 	$(CC) $(if $(DEBUG), -g) -Wall -Wextra -Werror -DBONUS=1 src/main.c -lasm -L. -o $(TEST_NAME)
# else
# 	$(CC) $(if $(DEBUG), -g) -Wall -Wextra -Werror src/main.c -lasm -L. -o $(TEST_NAME)
# endif
# 	@echo
# 	@./$(TEST_NAME)
#
# .PHONY: bonus_test
# bonus_test:
# 	$(MAKE) BONUS=1 test
#
# .PHONY: re_test
# re_test: fclean test
#
# .PHONY: re_bonus_test
# re_bonus_test:
# 	$(MAKE) BONUS=1 re_test
