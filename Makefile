NAME = ft_otp

all : ${NAME}

${NAME}:
	c++ -Wall -Wextra -Werror -g -fsanitize=address ft_otp.cpp -lssl -lcrypto -o ${NAME}

clean:
	rm -f ${NAME} ft_otp.key
fclean : clean

re : fclean all